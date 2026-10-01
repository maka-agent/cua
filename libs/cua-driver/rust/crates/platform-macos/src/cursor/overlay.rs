//! macOS agent-cursor overlay — transparent click-through NSWindow.
//!
//! ## Architecture
//!
//! The MCP/tokio server runs on a **background thread** (spawned in
//! `cua-driver/src/main.rs`).  AppKit MUST run on the **main thread**.
//! The two sides communicate through a global lock-free channel:
//!
//! - MCP tool calls → `send_command(OverlayCommand)` → `CMD_TX` (SyncSender)
//! - main thread → `run_on_main_thread()` → drains `CMD_RX` every frame
//!
//! The render loop uses a GCD background thread at ~60 fps.  Each tick it
//! renders the animation state into a `tiny_skia::Pixmap`, converts to a
//! `CGImage`, and dispatches `CALayer.setContents` back to the main queue.
//!
//! ## Coordinate system
//!
//! All coordinates are **screen points** with the **top-left origin**
//! (matching `OverlayCommand::MoveTo` and AX element coordinates).  The
//! Each display has a separate NSWindow and backing scale. AppKit bottom-left
//! frames are converted to the primary display's CG top-left coordinate space.
//!
//! ## Cross-platform note (2026-05 dedup audit)
//!
//! Animation state + render pipeline live in `cursor_overlay::render_state`
//! (`RenderStateCore`, `tick_swift_constants`, `apply_command_base`,
//! `render_frame`).  macOS uses the hardcoded Swift reference constants
//! (peakSpeed=900, springK=400, overshoot=0.8) and the sentinel-snap
//! variants of MoveTo / ClickPulse — see the wrapper around
//! `apply_command_base` below.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use cursor_overlay::{
    CursorConfig, CursorKey, FocusRect, KeyedOverlayCommand, MotionConfig, MsgOutcome,
    OverlayCommand, OverlayMsg, RenderEntry, RenderStateCore, ScreenFrame, ZOrderEnforcer,
};

// ── Arrival-signal channels (one waiter slot per cursor key) ──────────────
//
// Each session's `animate_cursor_to` registers an arrival oneshot keyed by its
// own cursor key. A new animation only supersedes the SAME key's prior waiter,
// so concurrent sessions never cross-cancel each other's arrivals.

static ARRIVAL_TX: Mutex<Option<HashMap<CursorKey, tokio::sync::oneshot::Sender<()>>>> =
    Mutex::new(None);

fn arrival_register(key: CursorKey, tx: tokio::sync::oneshot::Sender<()>) {
    let mut guard = ARRIVAL_TX.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    // Cancel only the same key's previous waiter (superseded by new animation).
    if let Some(old_tx) = map.insert(key, tx) {
        let _ = old_tx.send(());
    }
}

#[cfg(test)]
fn arrival_fire(key: &CursorKey) {
    if let Ok(mut guard) = ARRIVAL_TX.lock() {
        if let Some(map) = guard.as_mut() {
            if let Some(tx) = map.remove(key) {
                let _ = tx.send(());
            }
        }
    }
}

/// Drop a removed session's waiter; the dropped sender releases its await.
fn arrival_cancel(key: &CursorKey) {
    if let Ok(mut guard) = ARRIVAL_TX.lock() {
        if let Some(map) = guard.as_mut() {
            map.remove(key);
        }
    }
}

// ── Global overlay state ──────────────────────────────────────────────────

static CMD_TX: OnceLock<std::sync::mpsc::SyncSender<OverlayMsg>> = OnceLock::new();
// Single-consumer slot; receiver is moved into run_on_main_thread().
static CMD_RX_CELL: Mutex<Option<std::sync::mpsc::Receiver<OverlayMsg>>> = Mutex::new(None);
static RENDER: Mutex<Option<RenderMap>> = Mutex::new(None);
static OVERLAY_WINDOW_IDS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

pub(crate) fn is_overlay_window(window_id: u32) -> bool {
    window_id != 0
        && OVERLAY_WINDOW_IDS
            .lock()
            .is_ok_and(|ids| ids.contains(&window_id))
}

/// Screen-global geometry kept beside the shared keyed render map
/// ([`cursor_overlay::RenderMap`], which owns the per-session lifecycle:
/// lazy creation, stable z-order, tombstones, revival, and the default guard).
/// Written once in `run_appkit`.
#[derive(Default)]
struct MacScreen {
    surfaces: Vec<Surface>,
}

// Each NSScreen has its own AppKit backing scale. A union-sized window loses
// that relationship on mixed-DPI desktops and allocates pixels for gaps.
#[derive(Clone, Copy)]
struct Surface {
    frame: ScreenFrame,
    backing_scale: f64,
    layer_ptr: usize,
    win_ptr: usize,
    window_id: u32,
}
fn contains(frame: ScreenFrame, x: f64, y: f64) -> bool {
    x >= frame.x && y >= frame.y && x < frame.x + frame.width && y < frame.y + frame.height
}

fn cursor_screen<'a>(surfaces: &'a [Surface], state: &RenderState) -> Option<&'a Surface> {
    // MoveTo keeps the artwork centre 16 points behind the input point. The
    // centre may be outside a screen while the tip is legitimately on it.
    let x = state.core.pos.0 - state.core.heading.cos() * 16.0;
    let y = state.core.pos.1 - state.core.heading.sin() * 16.0;
    if let Some(surface) = surfaces
        .iter()
        .find(|surface| contains(surface.frame, x, y))
    {
        return Some(surface);
    }
    surfaces.iter().min_by(|a, b| {
        let distance = |frame: ScreenFrame| {
            let dx = (frame.x - x).max(0.0).max(x - frame.x - frame.width);
            let dy = (frame.y - y).max(0.0).max(y - frame.y - frame.height);
            dx * dx + dy * dy
        };
        distance(a.frame).total_cmp(&distance(b.frame))
    })
}

type RenderMap = cursor_overlay::RenderMap<RenderState, MacScreen>;

/// Drain one message into the shared map, releasing a removed session's
/// arrival waiter. Returns the commanded key for z-order pinning.
fn apply_msg(map: &mut RenderMap, msg: OverlayMsg) -> Option<CursorKey> {
    let outcome = map.apply_msg(msg);
    if let MsgOutcome::Removed { key, .. } = &outcome {
        arrival_cancel(key);
    }
    outcome.applied_key().cloned()
}

/// Initialise global overlay state (call once, before run_on_main_thread).
pub fn init(cfg: CursorConfig) {
    static INITIALIZED: OnceLock<()> = OnceLock::new();
    INITIALIZED.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel(4096);
        CMD_TX
            .set(tx)
            .expect("cursor overlay sender is initialized exactly once");
        *CMD_RX_CELL.lock().unwrap() = Some(rx);
        *ARRIVAL_TX.lock().unwrap() = Some(HashMap::new());
        *RENDER.lock().unwrap() = Some(RenderMap::new(cfg, MacScreen::default()));
    });
    cua_driver_core::cursor_events::install_cursor_event_sink(std::sync::Arc::new(
        |event: cua_driver_core::cursor_events::CursorEvent| {
            use cua_driver_core::cursor_events::{CursorEvent, CursorEventPhase};
            let (session, cmd) = match event {
                CursorEvent::SetSessionLabel { session, label } => {
                    (session, OverlayCommand::SetSessionLabel(label))
                }
                CursorEvent::Action {
                    session,
                    phase: CursorEventPhase::Begin,
                    semantics,
                } => (
                    session,
                    OverlayCommand::BeginAction {
                        action: semantics.action,
                        delivery: semantics.delivery,
                        target: semantics.target,
                    },
                ),
                CursorEvent::Action {
                    session,
                    phase: CursorEventPhase::End,
                    semantics,
                } => (session, OverlayCommand::EndAction(semantics.action)),
                CursorEvent::SelectTheme { session, selection } => (
                    session,
                    OverlayCommand::SetTheme {
                        theme_id: selection.theme_id,
                        reduced_motion: selection.reduced_motion,
                    },
                ),
            };
            send_command(session, cmd);
        },
    ));
}

/// Send a keyed command from any thread (MCP tool, etc.).  Non-blocking; drops
/// if the channel is full (old commands are less important than new ones).
pub fn send_command(key: CursorKey, cmd: OverlayCommand) {
    // Empty key is the explicit no-cursor sentinel for direct platform calls
    // that bypass lifecycle dispatch.
    if key.is_empty() {
        return;
    }
    if let Some(tx) = CMD_TX.get() {
        let _ = tx.try_send(OverlayMsg::Cmd(KeyedOverlayCommand { key, cmd }));
    }
}

/// Convenience for callsites not yet threaded with a session key: drives the
/// seeded `"default"` cursor (the anonymous / one-shot identity).
pub fn send_command_default(cmd: OverlayCommand) {
    send_command("default".to_owned(), cmd);
}

/// Truthful render acknowledgement for lifecycle inspection. This never falls
/// back to the seeded default cursor: an absent, off-screen, disabled, or
/// idle-faded session cursor is not reported as visible.
pub fn is_visible_for_session(key: &str) -> bool {
    RENDER
        .lock()
        .ok()
        .and_then(|guard| {
            guard.as_ref().and_then(|map| {
                map.cursors.get(key).map(|state| {
                    cursor_is_externally_visible(state)
                        && map.platform.surfaces.iter().any(|surface| {
                            contains(
                                surface.frame,
                                state.core.pos.0 - state.core.heading.cos() * 16.0,
                                state.core.pos.1 - state.core.heading.sin() * 16.0,
                            )
                        })
                })
            })
        })
        .unwrap_or(false)
}

/// Remove a session's owned cursor from the render collection (fired from the
/// `session_end` hook). The `"default"` key is guarded against removal on the
/// render side, so this is a no-op for it; removing an absent key (anonymous
/// session that never created a cursor) is a harmless no-op.
pub fn remove_cursor(key: CursorKey) {
    if key.is_empty() {
        return;
    }
    if let Some(tx) = CMD_TX.get() {
        let _ = tx.try_send(OverlayMsg::Remove(key));
    }
}

/// Clear the render-side tombstone after a successful explicit session
/// revival. Cursor recreation remains lazy until the next render command.
pub fn revive_cursor(key: CursorKey) {
    if key.is_empty() {
        return;
    }
    if let Some(tx) = CMD_TX.get() {
        let _ = tx.try_send(OverlayMsg::Revive(key));
    }
}

/// Return a snapshot of a cursor's current motion config (for use by
/// set_agent_cursor_motion to apply partial overrides without losing other
/// knobs). Reads the motion of the cursor `key`, falling back to the
/// `"default"` cursor's motion when that key has no own entry yet (e.g. a
/// session whose first motion call precedes any move/enable).
pub fn current_motion(key: &str) -> MotionConfig {
    let guard = RENDER.lock().unwrap();
    let Some(map) = guard.as_ref() else {
        return MotionConfig::default();
    };
    map.cursor_or_default(key)
        .map(|rs| rs.core.motion.clone())
        .unwrap_or_default()
}

/// Return the render-owned theme and semantic playback state for one cursor.
pub fn current_theme_state(
    key: &str,
) -> Option<(
    String,
    String,
    String,
    Option<String>,
    cursor_overlay::CursorVisualState,
)> {
    let guard = RENDER.lock().unwrap();
    let map = guard.as_ref()?;
    let state = map.cursor_or_default(key)?;
    let (id, version, profile, fallback) = state.core.active_theme_metadata();
    Some((id, version, profile, fallback, state.core.visual.clone()))
}

/// Seed a brand-new (sentinel-positioned) cursor at an on-screen start point
/// offset up-left of `(target_x, target_y)` so the immediately-following
/// `MoveTo` glides INTO the target instead of silently snapping. Without this,
/// a cursor's very first action (common on a pure-AX run — launch app, AX-press
/// a button) produces no visible motion: `animate_cursor_to` early-returned at
/// the sentinel and only `ClickPulse` snapped a static arrow, which is easy to
/// miss. See the AX-no-glide report.
///
/// No-op when the cursor has a position or is absent. The seed is clamped
/// to the target display, including displays with negative global coordinates.
/// Returns true if a seed was applied (i.e. the cursor was at the sentinel and
/// is now primed to glide).
fn seed_start_if_sentinel(key: &CursorKey, target_x: f64, target_y: f64) -> bool {
    let mut guard = RENDER.lock().unwrap();
    let Some(map) = guard.as_mut() else {
        return false;
    };
    let frame = map
        .platform
        .surfaces
        .iter()
        .find(|surface| contains(surface.frame, target_x, target_y))
        .map(|surface| surface.frame);
    map.seed_start_if_sentinel(key, target_x, target_y, frame)
}

/// Animate the overlay cursor to `(x, y)` and suspend until the Dubins path
/// completes and the spring overshoot begins.
///
/// Mirrors Swift's `AgentCursor.shared.animateAndWait(to:)`.
/// Returns immediately (no animation) only when the overlay is disabled for
/// this cursor. A brand-new cursor still at the off-screen sentinel is first
/// seeded on-screen via [`seed_start_if_sentinel`] so its FIRST action glides
/// in (it previously snapped silently via `ClickPulse`, invisible on a pure-AX
/// run).
pub async fn animate_cursor_to(key: CursorKey, x: f64, y: f64) {
    // Empty key is the explicit no-cursor sentinel → nothing to animate.
    if key.is_empty() {
        return;
    }
    // Seed a sentinel cursor on-screen so the MoveTo below glides instead of
    // being short-circuited. After this the cursor has a position, so the
    // should-animate check passes on the first action just like later ones.
    seed_start_if_sentinel(&key, x, y);

    // Check whether animation should run for THIS cursor. A disabled cursor
    // never animates; an absent cursor (seed found nothing to prime) is skipped.
    let should_animate = {
        let guard = RENDER.lock().unwrap();
        matches!(
            guard.as_ref().and_then(|m| m.cursors.get(&key)),
            Some(rs) if rs.core.cfg.enabled && rs.core.positioned
        )
    };
    if !should_animate {
        return;
    }

    // Create a one-shot channel; store the sender (keyed) so the render thread
    // can fire it when this cursor's path finishes.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    arrival_register(key.clone(), tx);

    // Send the MoveTo command (click offset applied inside apply_command).
    send_command(
        key,
        OverlayCommand::MoveTo {
            x,
            y,
            // Arrive pointing upper-left (45°), matching the macOS system-cursor
            // convention and Swift reference (`endAngleDegrees: 45`).
            end_heading_radians: std::f64::consts::FRAC_PI_4,
        },
    );

    // Await arrival signal (fired from render thread when Dubins path ends).
    let _ = rx.await;
}

/// Block the calling thread (must be the OS main thread) running the AppKit
/// event loop and the overlay window.  Never returns normally.
///
/// Call this from `main()` after spawning the tokio background thread.
pub fn run_on_main_thread() {
    // Take the receiver.
    let rx = match CMD_RX_CELL.lock().unwrap().take() {
        Some(r) => r,
        None => {
            // init() was never called — no overlay, just spin.
            loop {
                std::thread::park();
            }
        }
    };

    let cfg = {
        let guard = RENDER.lock().unwrap();
        match guard.as_ref() {
            Some(m) => m.template.clone(),
            None => return,
        }
    };

    if !cfg.enabled {
        loop {
            std::thread::park();
        }
    }

    // AppKit's `+[NSApplication sharedApplication]` registers the process with
    // the Window Server and ABORTS the whole process (SIGABRT in
    // `_RegisterApplication`) when there's no graphic-session access — e.g.
    // `mcp` run as a stdio child from SSH, a LaunchDaemon, or headless CI.
    // Detect that without touching AppKit and run headless: the MCP server
    // keeps serving on its background thread while this thread just parks,
    // exactly as it does when the overlay is disabled. See issue #1724.
    if !crate::session::has_graphic_access() {
        tracing::warn!(
            "no Window Server / graphic-session access — skipping cursor \
             overlay and running headless (issue #1724)"
        );
        loop {
            std::thread::park();
        }
    }

    // ------------------------------------------------------------------
    // AppKit setup (all on the main thread).
    // ------------------------------------------------------------------
    unsafe { run_appkit(cfg, rx) };
}

// ── Animation / render state ──────────────────────────────────────────────
//
// The platform-agnostic fields + tick + apply_command + render pipeline live
// in `cursor_overlay::render_state` (2026-05 dedup audit). What stays here
// is the macOS-specific NSScreen window dimensions and the focus-rect
// overlay (a macOS-only post-arrival element highlight).

struct RenderState {
    core: RenderStateCore,
    /// Focus-highlight rectangle `[x, y, w, h]` in screen coords; None = not shown.
    focus_rect: Option<[f64; 4]>,
    /// Fade progress for the focus rect: 0.0 = fully visible, 1.0 = gone.
    focus_rect_t: f64,
}

impl RenderEntry for RenderState {
    fn from_config(cfg: CursorConfig) -> Self {
        RenderState {
            core: RenderStateCore::new(cfg),
            focus_rect: None,
            focus_rect_t: 1.0,
        }
    }

    fn core(&self) -> &RenderStateCore {
        &self.core
    }

    fn core_mut(&mut self) -> &mut RenderStateCore {
        &mut self.core
    }

    /// Advance the animation by `dt`.  Uses the Swift reference constants
    /// (peakSpeed=900, springK=400, overshoot=0.8) — see
    /// [`RenderStateCore::tick_swift_constants`].  Returns true if an
    /// arrival signal should be fired (the path just ended).
    fn tick(&mut self, dt: f64) -> bool {
        let fire_arrival = self.core.tick_swift_constants(dt);

        // Advance focus-rect fade (fades out over ~600ms).  macOS-only —
        // the shared core has no focus_rect concept.
        if self.focus_rect.is_some() {
            self.focus_rect_t = (self.focus_rect_t + dt / 0.6).min(1.0);
            if self.focus_rect_t >= 1.0 {
                self.focus_rect = None;
                self.focus_rect_t = 1.0;
            }
        }

        fire_arrival
    }

    fn apply_command(&mut self, cmd: OverlayCommand) -> bool {
        // macOS uses the sentinel-snap variants of MoveTo / ClickPulse:
        //   - MoveTo only snaps `self.pos` if the cursor is still at the
        //     off-screen sentinel `(-200, -200)` (otherwise the path starts
        //     from the current position so the animation is continuous).
        //   - ClickPulse only updates `self.pos` if the cursor is still at
        //     the sentinel (otherwise the animation already landed it there).
        match cmd {
            OverlayCommand::ShowFocusRect(rect) => {
                self.focus_rect = rect;
                self.focus_rect_t = 0.0; // reset fade to fully visible
                true
            }
            OverlayCommand::PinAbove(wid) => {
                // The overlay window joins every Space, so a target on another
                // Space would otherwise animate over the user's current one at
                // that window's coordinates. Unknown membership keeps painting.
                self.core.pinned_target_off_workspace = u32::try_from(wid)
                    .ok()
                    .and_then(crate::windows::window_on_current_space_by_id)
                    == Some(false);
                self.core.apply_command_base(cmd, true, true)
            }
            other => self.core.apply_command_base(other, true, true),
        }
    }

    /// The shared predicate (glide, spring, pulse, badge, resting motion,
    /// idle fade) plus two macOS terms: the focus-rect fade, and the opaque
    /// idle-hide countdown. The macOS loop parks on a blocking `recv` with no
    /// deadline, so a reduced-motion cursor must keep frame ticks through the
    /// countdown for its idle fade to start on time.
    fn needs_frame_tick(&self) -> bool {
        self.core.needs_frame_tick()
            || self.focus_rect.is_some()
            || (self.core.motion.idle_hide_ms > 0.0
                && self.core.visible
                && self.core.positioned
                && self.core.idle_alpha >= 0.004)
    }
}

// ── AppKit / CGImage plumbing ─────────────────────────────────────────────

unsafe fn run_appkit(_cfg: CursorConfig, rx: std::sync::mpsc::Receiver<OverlayMsg>) {
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};
    use objc2_foundation::NSRect;

    // ---- NSApplication ----
    // Verify main thread (MainThreadMarker is a zero-size compile-time token).
    let _mtm = objc2_foundation::MainThreadMarker::new()
        .expect("run_appkit must be called from the main thread");

    let app: *mut AnyObject = msg_send![class!(NSApplication), sharedApplication];
    // NSApplicationActivationPolicyAccessory = 1 (no Dock icon, no menu bar)
    // setActivationPolicy: returns BOOL (success), not void.
    let _: bool = msg_send![app, setActivationPolicy: 1i64];
    // Finish launching without presenting a UI (needed for NSApp.run())
    let _: () = msg_send![app, finishLaunching];

    let screens: *mut AnyObject = msg_send![class!(NSScreen), screens];
    let count: usize = msg_send![screens, count];
    if count == 0 {
        return;
    }
    // The first NSScreen is the primary display; mainScreen follows the key
    // window and is therefore unsuitable as the fixed CG coordinate origin.
    let primary: *mut AnyObject = msg_send![screens, objectAtIndex: 0usize];
    let primary_frame: NSRect = msg_send![primary, frame];
    let primary_top = primary_frame.origin.y + primary_frame.size.height;
    let mut surfaces = Vec::new();
    for index in 0..count {
        let screen: *mut AnyObject = msg_send![screens, objectAtIndex: index];
        let screen_frame: NSRect = msg_send![screen, frame];
        let mut backing_scale: f64 = msg_send![screen, backingScaleFactor];
        if !backing_scale.is_finite() || backing_scale < 1.0 {
            backing_scale = 1.0;
        }
        // ---- NSWindow: single alloc + initWithContentRect:... ----
        let win: *mut AnyObject = {
            let allocated: *mut AnyObject = msg_send![class!(NSWindow), alloc];
            // NSWindowStyleMaskBorderless = 0
            // NSBackingStoreBuffered = 2
            let w: *mut AnyObject = msg_send![allocated,
                initWithContentRect: screen_frame
                styleMask: 0u64
                backing: 2u64
                defer: false
            ];
            w
        };
        if win.is_null() {
            continue;
        }

        let _: () = msg_send![win, setOpaque: false];
        let clear: *mut AnyObject = msg_send![class!(NSColor), clearColor];
        let _: () = msg_send![win, setBackgroundColor: clear];
        let _: () = msg_send![win, setHasShadow: false];
        let _: () = msg_send![win, setIgnoresMouseEvents: true];
        // NSWindowSharingReadOnly = 1. AppKit documents this as the default, but
        // set it explicitly for the transparent agent overlay so ScreenCaptureKit
        // includes browser-session cursors in Cua Driver recordings. Tahoe can
        // otherwise show the overlay live while omitting it from an in-process
        // display recording.
        let _: () = msg_send![win, setSharingType: 1u64];
        // NSNormalWindowLevel = 0.  The overlay lives at the normal window level so
        // it appears in CGWindowList layer=0 results (which agents inspect via
        // list_windows).  Z-ordering above the target is managed dynamically via
        // orderWindow:relativeTo: (see dispatch_pin_above / render_loop repin).
        let _: () = msg_send![win, setLevel: 0i64];
        // NSWindowCollectionBehaviorCanJoinAllSpaces(1<<0) | FullScreenAuxiliary(1<<8) | Stationary(1<<4)
        let _: () = msg_send![win, setCollectionBehavior: (1u64 | (1<<8) | (1<<4))];
        let _: () = msg_send![win, setReleasedWhenClosed: false];
        let _: () = msg_send![win, setHidesOnDeactivate: false];

        // ---- Layer-backed content view ----
        let content_view: *mut AnyObject = msg_send![win, contentView];
        let _: () = msg_send![content_view, setWantsLayer: true];
        let layer: *mut AnyObject = msg_send![content_view, layer];

        // Set layer geometry. contentsScale tells Core Animation that the CGImage
        // we hand to setContents: is already at retina (`backing_scale`×) pixel
        // density — without this, CA would treat our physical-pixel pixmap as a
        // 1× asset and bilinear-downsample it back to logical pixels on screen,
        // re-introducing the blur this pipeline exists to eliminate.
        let _: () = msg_send![layer, setContentsScale: backing_scale];
        // kCAGravityTopLeft — the string literal "topLeft"
        let gravity_ns: *mut AnyObject = msg_send![class!(NSString),
            stringWithUTF8String: c"topLeft".as_ptr().cast::<u8>()
        ];
        let _: () = msg_send![layer, setContentsGravity: gravity_ns];

        let window_number: isize = msg_send![win, windowNumber];
        surfaces.push(Surface {
            frame: ScreenFrame::new(
                screen_frame.origin.x,
                primary_top - screen_frame.origin.y - screen_frame.size.height,
                screen_frame.size.width,
                screen_frame.size.height,
            ),
            backing_scale,
            layer_ptr: layer as usize,
            win_ptr: win as usize,
            window_id: u32::try_from(window_number).unwrap_or(0),
        });
        let _: () = msg_send![win, orderFrontRegardless];
    }
    *OVERLAY_WINDOW_IDS.lock().unwrap() =
        surfaces.iter().map(|surface| surface.window_id).collect();
    if let Some(map) = RENDER.lock().unwrap().as_mut() {
        map.platform = MacScreen { surfaces };
    }
    std::thread::spawn(move || render_loop(rx));

    // ---- NSApplication run loop (blocks until process exits) ----
    let _: () = msg_send![app, run];
    OVERLAY_WINDOW_IDS.lock().unwrap().clear();
}

fn render_loop(rx: std::sync::mpsc::Receiver<OverlayMsg>) {
    let target_frame_ms = Duration::from_millis(16); // ~60 fps while pixels can change
    let hover_poll_ms = Duration::from_millis(80);
    let mut last_tick = Instant::now();
    let mut frame_tick_needed = false;
    let mut hover_poll_needed = false;
    // Repin bookkeeping: track last pinned wid and a frame counter for
    // the periodic defensive-repin (every ~60 active frames ≈ 1 s).
    let mut last_pinned: Option<u64> = None;
    let mut repin_frames: u32 = 0;

    loop {
        // When no cursor animation/fade is active, block until the MCP side
        // sends a command. This is the idle-server fast path: no fullscreen
        // pixmap allocation, no CGImage conversion, no 60fps wakeup.
        let (first_msg, hover_poll_tick) = if frame_tick_needed {
            (None, hover_poll_needed)
        } else if hover_poll_needed {
            match rx.recv_timeout(hover_poll_ms) {
                Ok(msg) => (Some(msg), true),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => (None, true),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match rx.recv() {
                Ok(msg) => (Some(msg), false),
                Err(_) => break,
            }
        };

        let woke_from_idle = first_msg.is_some();
        let now = Instant::now();
        let dt = if woke_from_idle {
            // The blocking recv() above can span an arbitrarily long idle period.
            // Do not charge that time to the first animation tick after a command;
            // let the wake-up frame render the newly-applied state at t=0.
            0.0
        } else {
            now.duration_since(last_tick).as_secs_f64().min(0.05)
        };
        last_tick = now;

        // ── Phase 1: drain + tick all cursors (one lock acquisition) ──────
        // `pinned_wid` follows the most-recently-updated cursor: a single
        // NSWindow can occupy only one z-band, so the last-active cursor's
        // target wins. `arrived` collects the keys whose path just ended.
        let (
            pinned_wid,
            raise_unpinned,
            arrived,
            surfaces,
            had_msg,
            hover_changed,
            next_frame_tick_needed,
            next_hover_poll_needed,
        ) = {
            let mut guard = RENDER.lock().unwrap();
            match guard.as_mut() {
                Some(map) => {
                    // Drain via get-or-create; track the last-touched key so we
                    // can read its pinned_wid after ticking.
                    let mut last_key: Option<CursorKey> = None;
                    let mut had_msg = false;
                    if let Some(msg) = first_msg {
                        had_msg = true;
                        if let Some(k) = apply_msg(map, msg) {
                            last_key = Some(k);
                        }
                    }
                    while let Ok(msg) = rx.try_recv() {
                        had_msg = true;
                        if let Some(k) = apply_msg(map, msg) {
                            last_key = Some(k);
                        }
                    }
                    // Tick every cursor while an animation/fade is in progress
                    // or immediately after a command changed render state. The
                    // latter lets a just-created path/click/focus rect start on
                    // this frame without waiting for the next 16ms tick.
                    let mut arrived: Vec<CursorKey> = Vec::new();
                    if frame_tick_needed || had_msg {
                        arrived = map.tick_all(dt);
                    }
                    let pointer = if hover_poll_tick
                        || map
                            .cursors
                            .values()
                            .any(|rs| rs.core.session_badge_needs_hover_poll())
                    {
                        hardware_cursor_position()
                    } else {
                        None
                    };
                    let mut hover_changed = false;
                    if pointer.is_some() || hover_poll_tick {
                        for rs in map.cursors.values_mut() {
                            hover_changed |= rs.core.update_session_badge_hover(pointer);
                        }
                    }
                    let pinned = last_key
                        .as_ref()
                        .and_then(|k| map.cursors.get(k))
                        .map(|rs| rs.core.pinned_wid)
                        .unwrap_or(last_pinned);
                    let raise_unpinned = last_key
                        .as_ref()
                        .and_then(|k| map.cursors.get(k))
                        .is_some_and(cursor_is_externally_visible)
                        && pinned.is_none();
                    let next_frame_tick_needed = map.needs_frame_tick();
                    let next_hover_poll_needed = map
                        .cursors
                        .values()
                        .any(|rs| rs.core.session_badge_needs_hover_poll());
                    (
                        pinned,
                        raise_unpinned,
                        arrived,
                        map.platform.surfaces.clone(),
                        had_msg,
                        hover_changed,
                        next_frame_tick_needed,
                        next_hover_poll_needed,
                    )
                }
                None => break,
            }
        };

        // Repin: immediately on target change, then defensive every ~1 s while
        // the render loop is active. When quiescent, z-order is left unchanged
        // until the next command wakes the loop.
        if frame_tick_needed || had_msg {
            repin_frames += 1;
            let pin_changed = pinned_wid != last_pinned;
            last_pinned = pinned_wid;
            if pinned_wid.is_some() && (pin_changed || repin_frames >= 60) {
                for surface in &surfaces {
                    MacZOrderEnforcer {
                        win_ptr: surface.win_ptr,
                    }
                    .reassert(pinned_wid);
                }
                repin_frames = 0;
            } else if raise_unpinned {
                // A direct move_cursor has no target window to pin against.
                // Raise the normal-level, click-through overlay without
                // activating the driver so a later foreground application
                // cannot cover a standalone session cursor.
                for surface in &surfaces {
                    dispatch_order_front(surface.win_ptr);
                }
                repin_frames = 0;
            } else if repin_frames >= 60 {
                repin_frames = 0;
            }
        }

        // ── Phase 2: composite every cursor into ONE pixmap ───────────────
        // Render only when a command arrived or the previous/next tick can
        // change pixels. A final frame is emitted as animations/fades finish so
        // the layer is left in the completed/cleared state before blocking.
        if had_msg || hover_changed || frame_tick_needed || next_frame_tick_needed {
            let frames = {
                let guard = RENDER.lock().unwrap();
                let Some(map) = guard.as_ref() else {
                    break;
                };
                let mut frames = Vec::new();
                for surface in &surfaces {
                    let scale = surface.backing_scale;
                    let mut pm = match tiny_skia::Pixmap::new(
                        (surface.frame.width * scale) as u32,
                        (surface.frame.height * scale) as u32,
                    ) {
                        Some(pm) => pm,
                        None => return,
                    };
                    for rs in map.cursors.values() {
                        // Badges are laid out on their cursor's display, then
                        // clipped by each surface. They cannot be clamped and
                        // duplicated on unrelated displays.
                        let Some(owner) = cursor_screen(&surfaces, rs) else {
                            continue;
                        };
                        let viewport = tiny_skia::Rect::from_xywh(
                            owner.frame.x as f32,
                            owner.frame.y as f32,
                            owner.frame.width as f32,
                            owner.frame.height as f32,
                        )
                        .unwrap();
                        let focus = rs.focus_rect.map(|rect| FocusRect {
                            rect,
                            t: rs.focus_rect_t,
                        });
                        cursor_overlay::paint_cursor_in_viewport(
                            &mut pm,
                            &rs.core,
                            surface.frame.x,
                            surface.frame.y,
                            focus,
                            scale as f32,
                            viewport,
                        );
                    }
                    frames.push((surface.layer_ptr, pm));
                }
                frames
            };

            // Convert to CGImage and update layer on the main queue.
            // Capture these waiters now: a newer movement can reuse a key
            // before the main queue applies this frame.
            let arrivals = {
                let mut guard = ARRIVAL_TX.lock().unwrap();
                arrived
                    .iter()
                    .filter_map(|key| guard.as_mut()?.remove(key))
                    .collect()
            };
            dispatch_set_layer_contents(frames, arrivals);
        }

        frame_tick_needed = next_frame_tick_needed;
        hover_poll_needed = next_hover_poll_needed;
        if frame_tick_needed {
            // Sleep remainder of frame budget.
            let elapsed = Instant::now().duration_since(last_tick);
            if let Some(remaining) = target_frame_ms.checked_sub(elapsed) {
                std::thread::sleep(remaining);
            }
        }
    }
}

fn hardware_cursor_position() -> Option<(f64, f64)> {
    use core_graphics::{
        event::CGEvent,
        event_source::{CGEventSource, CGEventSourceStateID},
    };

    let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState).ok()?;
    let event = CGEvent::new(source).ok()?;
    let location = event.location();
    Some((location.x, location.y))
}

fn cursor_is_externally_visible(state: &RenderState) -> bool {
    state.core.cfg.enabled
        && state.core.visible
        && !state.core.pinned_target_off_workspace
        && state.core.positioned
        && state.core.idle_alpha >= 0.004
}

/// Convert a `tiny_skia::Pixmap` to a `CGImage` and set it as the contents
/// of the given `CALayer` via `dispatch_async(main_queue, ...)`.
fn dispatch_set_layer_contents(
    frames: Vec<(usize, tiny_skia::Pixmap)>,
    arrivals: Vec<tokio::sync::oneshot::Sender<()>>,
) {
    let mut images = Vec::new();
    for (layer, pixmap) in frames {
        match pixmap_to_cgimage(&pixmap) {
            Some(image) => images.push((layer, image)),
            None => {
                for (_, image) in images {
                    unsafe {
                        CGImageRelease(image as *mut c_void);
                    }
                }
                return;
            }
        }
    }
    let payload = Box::new((images, arrivals));

    // GCD symbols from libdispatch (part of the macOS system library stubs).
    // `dispatch_get_main_queue()` is an inline C function; the underlying
    // symbol is `_dispatch_main_q`, a *struct* (not a pointer).
    // We declare it as `u8` (opaque placeholder) and take its ADDRESS to
    // obtain the `dispatch_queue_t` (pointer to the struct).
    #[link(name = "System", kind = "framework")]
    extern "C" {
        // Opaque placeholder — we only ever take &_dispatch_main_q, never read it.
        static _dispatch_main_q: u8;
        fn dispatch_async_f(
            queue: *const c_void,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
    }

    unsafe extern "C" fn set_contents_cb(ctx: *mut c_void) {
        let (images, arrivals): (Vec<(usize, usize)>, Vec<tokio::sync::oneshot::Sender<()>>) =
            *Box::from_raw(ctx as *mut _);
        for (layer_ptr, image) in &images {
            let layer = *layer_ptr as *mut objc2::runtime::AnyObject;
            let cg_id = *image as *mut objc2::runtime::AnyObject;
            let _: () = objc2::msg_send![layer, setContents: cg_id];
        }
        let _: () = objc2::msg_send![objc2::class!(CATransaction), flush];
        // A path-end notification belongs to the applied frame, not to an
        // earlier model tick or merely scheduling this callback.
        for arrival in arrivals {
            let _ = arrival.send(());
        }
        // Release the CGImage ref we retained in pixmap_to_cgimage.
        for (_, image) in images {
            CGImageRelease(image as *mut c_void);
        }
    }

    extern "C" {
        fn CGImageRelease(image: *mut c_void);
    }

    unsafe {
        // &_dispatch_main_q is the queue pointer (same as dispatch_get_main_queue()).
        let main_queue = &raw const _dispatch_main_q as *const c_void;
        dispatch_async_f(
            main_queue,
            Box::into_raw(payload) as *mut c_void,
            set_contents_cb,
        );
    }
}

/// Raise the normal-level overlay without activating the driver application.
///
/// This is used only for an externally visible cursor with no target window.
/// Target-bound actions continue to use [`dispatch_pin_above`] so background
/// delivery remains below unrelated foreground applications.
fn dispatch_order_front(win_ptr: usize) {
    use std::ffi::c_void;

    #[link(name = "System", kind = "framework")]
    extern "C" {
        static _dispatch_main_q: u8;
        fn dispatch_async_f(
            queue: *const c_void,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
    }

    unsafe extern "C" fn order_front_cb(ctx: *mut c_void) {
        let win_ptr = *Box::from_raw(ctx as *mut usize);
        let win = win_ptr as *mut objc2::runtime::AnyObject;
        let _: () = objc2::msg_send![win, orderFrontRegardless];
    }

    let payload = Box::new(win_ptr);
    unsafe {
        let main_queue = &raw const _dispatch_main_q as *const c_void;
        dispatch_async_f(
            main_queue,
            Box::into_raw(payload) as *mut c_void,
            order_front_cb,
        );
    }
}

/// Order the overlay NSWindow just above `target_wid` in the global window
/// server list.  Called from the render thread; dispatches to the main queue
/// (AppKit must be used on the main thread).
///
/// `NSWindowAbove = 1`; `orderWindow:relativeTo:` accepts any CGWindowID as
/// the `relativeTo` argument — it works cross-application via CGS.
fn target_is_frontmost_visible_window(
    target_wid: u64,
    frontmost_pid: Option<i32>,
    windows: &[crate::windows::WindowInfo],
) -> bool {
    let Some(target) = windows
        .iter()
        .find(|window| u64::from(window.window_id) == target_wid)
    else {
        return false;
    };
    if !target.is_on_screen || target.layer != 0 || frontmost_pid != Some(target.pid) {
        return false;
    }

    windows
        .iter()
        .filter(|window| {
            window.is_on_screen
                && window.layer == 0
                && window.pid == target.pid
                && window.bounds.width > 1.0
                && window.bounds.height > 1.0
        })
        .max_by_key(|window| window.z_index)
        .is_some_and(|window| u64::from(window.window_id) == target_wid)
}

fn dispatch_pin_above(win_ptr: usize, target_wid: u64) {
    use std::ffi::c_void;

    #[link(name = "System", kind = "framework")]
    extern "C" {
        static _dispatch_main_q: u8;
        fn dispatch_async_f(
            queue: *const c_void,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
    }

    unsafe extern "C" fn reorder_cb(ctx: *mut c_void) {
        let (win_ptr, target_wid, raise_front): (usize, u64, bool) =
            *Box::from_raw(ctx as *mut (usize, u64, bool));
        let win = win_ptr as *mut objc2::runtime::AnyObject;
        // NSWindowAbove = 1; relativeTo: takes NSInteger (i64 on 64-bit)
        let _: () = objc2::msg_send![win, orderWindow: 1i64 relativeTo: target_wid as i64];

        // Tahoe can leave a normal-level transparent window behind an
        // already-frontmost cross-process target even after the relative
        // ordering request. `orderFrontRegardless` does not activate the
        // driver app. Use it only when the exact target is already the
        // frontmost visible normal window, so background browser actions do
        // not put the overlay above the user's foreground app.
        if raise_front {
            let _: () = objc2::msg_send![win, orderFrontRegardless];
        }
    }

    let windows = crate::windows::visible_windows();
    let raise_front =
        target_is_frontmost_visible_window(target_wid, crate::apps::frontmost_pid(), &windows);
    let payload = Box::new((win_ptr, target_wid, raise_front));
    unsafe {
        let main_queue = &raw const _dispatch_main_q as *const c_void;
        dispatch_async_f(
            main_queue,
            Box::into_raw(payload) as *mut c_void,
            reorder_cb,
        );
    }
}

// ── Z-order enforcer (macOS impl of cursor_overlay::ZOrderEnforcer) ──────

/// macOS implementation of [`cursor_overlay::ZOrderEnforcer`].
///
/// Holds the NSWindow pointer as a `usize` and dispatches the
/// `orderWindow:relativeTo:` call to the main queue (AppKit must run on
/// the main thread).
///
/// `target = None` is treated as a no-op here. Direct unpinned cursor commands
/// raise the overlay once in the render loop, while this enforcer remains
/// responsible only for target-relative ordering.
struct MacZOrderEnforcer {
    win_ptr: usize,
}

impl ZOrderEnforcer for MacZOrderEnforcer {
    fn reassert(&self, target: Option<u64>) {
        if let Some(wid) = target {
            dispatch_pin_above(self.win_ptr, wid);
        }
        // target = None → no-op; see struct doc comment.
    }
}

/// Create a `CGImage` from a `tiny_skia::Pixmap` (premultiplied RGBA).
/// Returns a `+1` retained pointer that the caller must release.
fn pixmap_to_cgimage(pixmap: &tiny_skia::Pixmap) -> Option<usize> {
    let w = pixmap.width() as usize;
    let h = pixmap.height() as usize;
    if w == 0 || h == 0 {
        return None;
    }

    let data = pixmap.data();
    let bytes_per_row = w * 4;

    // tiny-skia produces premultiplied RGBA with bytes in memory order [R, G, B, A].
    // CGImage flag breakdown (Apple CGBitmapInfo / CGImageAlphaInfo enums):
    //   kCGImageAlphaPremultipliedLast = 0x0001  → alpha is the LAST channel  (RGBA)
    //   kCGImageAlphaPremultipliedFirst = 0x0002 → alpha is the FIRST channel (ARGB)  ← NOT what we want
    //   kCGBitmapByteOrder32Big        = 0x4000  → big-endian 32-bit pixel,
    //     so memory order is the same as component order (bytes = [R, G, B, A]).
    // Combined: kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big = 0x4001
    // This correctly maps tiny-skia's [R, G, B, A] bytes to the display RGB channels.
    const BITMAP_INFO: u32 = 0x0001 | 0x4000; // kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big

    // Release callback: CGDataProvider calls this when it is done with the buffer.
    // `info` is the Box<Vec<u8>> we passed as the `info` argument below.
    unsafe extern "C" fn release_pixel_data(info: *mut c_void, _data: *const c_void, _size: usize) {
        // Re-box and drop to free the buffer.
        drop(Box::from_raw(info as *mut Vec<u8>));
    }

    unsafe {
        extern "C" {
            fn CGColorSpaceCreateDeviceRGB() -> *mut c_void;
            fn CGColorSpaceRelease(cs: *mut c_void);
            fn CGDataProviderCreateWithData(
                info: *mut c_void,
                data: *const c_void,
                size: usize,
                release_data: Option<unsafe extern "C" fn(*mut c_void, *const c_void, usize)>,
            ) -> *mut c_void;
            fn CGDataProviderRelease(provider: *mut c_void);
            fn CGImageCreate(
                width: usize,
                height: usize,
                bits_per_component: usize,
                bits_per_pixel: usize,
                bytes_per_row: usize,
                color_space: *mut c_void,
                bitmap_info: u32,
                provider: *mut c_void,
                decode: *const f64,
                should_interpolate: bool,
                intent: u32,
            ) -> *mut c_void;
        }

        // Copy the pixel data into a heap Vec; the data provider will own it
        // and free it via release_pixel_data when the CGImage is released.
        let copied: Vec<u8> = data.to_vec();
        let len = copied.len();
        let ptr = copied.as_ptr();
        // Leak the Vec into a raw Box so we can pass it as the `info` opaque pointer.
        let copied_box: *mut Vec<u8> = Box::into_raw(Box::new(copied));

        let cs = CGColorSpaceCreateDeviceRGB();
        let provider = CGDataProviderCreateWithData(
            copied_box as *mut c_void,
            ptr as *const c_void,
            len,
            Some(release_pixel_data), // frees copied_box when provider is released
        );
        let img = CGImageCreate(
            w,
            h,
            8,  // bits_per_component
            32, // bits_per_pixel
            bytes_per_row,
            cs,
            BITMAP_INFO,
            provider,
            std::ptr::null(),
            false,
            0, // kCGRenderingIntentDefault
        );

        CGColorSpaceRelease(cs);
        CGDataProviderRelease(provider);
        // Do NOT drop copied_box here — release_pixel_data owns it now.

        if img.is_null() {
            None
        } else {
            Some(img as usize)
        }
    }
}

// ── Headless unit tests for the keyed render collection ───────────────────
//
// These prove the per-session ownership data model, the session_end removal
// lifecycle, the "default" guard, and per-key arrival isolation WITHOUT any
// AppKit / NSWindow. The on-screen rendering (CGImage / CALayer setContents)
// still needs a real display and is verified separately on the macOS VM.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // The keyed lifecycle, sentinel seed, and shared frame-tick predicate are
    // covered once in `cursor_overlay::render_map`. These tests cover only the
    // macOS adapter: window ordering, external visibility, and the macOS
    // frame-tick terms layered on the shared predicate.

    fn window(window_id: u32, pid: i32, z_index: usize) -> crate::windows::WindowInfo {
        crate::windows::WindowInfo {
            window_id,
            pid,
            app_name: format!("app-{pid}"),
            title: String::new(),
            bounds: crate::windows::WindowBounds {
                x: 0.0,
                y: 0.0,
                width: 800.0,
                height: 600.0,
            },
            layer: 0,
            z_index,
            is_on_screen: true,
            current_space_id: None,
            on_current_space: None,
            space_ids: None,
        }
    }

    fn empty_map() -> RenderMap {
        RenderMap::new(
            CursorConfig::default(),
            MacScreen {
                surfaces: vec![Surface {
                    frame: ScreenFrame::new(0.0, 0.0, 100.0, 100.0),
                    backing_scale: 1.0,
                    layer_ptr: 0,
                    win_ptr: 0,
                    window_id: 0,
                }],
            },
        )
    }

    fn placed<'a>(map: &'a mut RenderMap, key: &str) -> &'a mut RenderState {
        let frame = Some(ScreenFrame::new(0.0, 0.0, 100.0, 100.0));
        assert!(map.seed_start_if_sentinel(key, 60.0, 60.0, frame));
        map.cursors.get_mut(key).unwrap()
    }

    #[test]
    fn frontmost_target_can_raise_overlay_without_covering_another_app() {
        let target_pid = 100;
        let mut windows = vec![window(10, target_pid, 20), window(11, 200, 10)];
        // WindowServer may retain another app's window ahead in its global
        // list; the active app identity is the authoritative cross-app guard.
        windows[1].z_index = 30;
        assert!(target_is_frontmost_visible_window(
            10,
            Some(target_pid),
            &windows,
        ));

        // A different foreground app blocks the fallback raise.
        assert!(!target_is_frontmost_visible_window(10, Some(200), &windows,));

        // So does another visible window belonging to the active target app.
        windows.push(window(13, target_pid, 40));
        assert!(!target_is_frontmost_visible_window(
            10,
            Some(target_pid),
            &windows,
        ));
    }

    #[test]
    fn screen_owner_follows_the_tip_at_edges_and_negative_display_origins() {
        let mut map = empty_map();
        let mut right = map.platform.surfaces[0];
        right.frame = ScreenFrame::new(100.0, 0.0, 100.0, 100.0);
        map.platform.surfaces.push(right);
        let core = &mut placed(&mut map, "edge").core;
        core.pos = (
            100.0 + 16.0 * core.heading.cos(),
            50.0 + 16.0 * core.heading.sin(),
        );
        let frame = cursor_screen(&map.platform.surfaces, &map.cursors["edge"])
            .unwrap()
            .frame;
        assert_eq!(
            frame.x, 100.0,
            "a shared edge belongs to the display containing the tip"
        );
        map.cursors.get_mut("edge").unwrap().core.pos = (211.0, 111.0);
        assert_eq!(
            cursor_screen(&map.platform.surfaces, &map.cursors["edge"])
                .unwrap()
                .frame
                .x,
            100.0
        );
        map.platform.surfaces[0].frame = ScreenFrame::new(-300.0, -200.0, 100.0, 100.0);
        map.cursors.get_mut("edge").unwrap().core.pos = (-250.0, -150.0);
        assert_eq!(
            cursor_screen(&map.platform.surfaces, &map.cursors["edge"])
                .unwrap()
                .frame
                .x,
            -300.0
        );
    }

    #[test]
    fn only_enabled_on_screen_cursor_is_externally_visible() {
        let mut map = empty_map();
        assert!(!cursor_is_externally_visible(&map.cursors["default"]));

        placed(&mut map, "sessA");
        assert!(cursor_is_externally_visible(&map.cursors["sessA"]));

        map.cursors.get_mut("sessA").unwrap().core.cfg.enabled = false;
        assert!(!cursor_is_externally_visible(&map.cursors["sessA"]));
    }

    #[test]
    fn removal_through_the_adapter_releases_only_that_arrival_waiter() {
        let mut map = empty_map();
        assert_eq!(
            apply_msg(
                &mut map,
                OverlayMsg::Cmd(KeyedOverlayCommand {
                    key: "sessA".to_owned(),
                    cmd: OverlayCommand::SetEnabled(true),
                }),
            )
            .as_deref(),
            Some("sessA")
        );
        assert_eq!(
            apply_msg(&mut map, OverlayMsg::Remove("sessA".to_owned())),
            None
        );
        assert!(!map.cursors.contains_key("sessA"));
    }

    #[test]
    fn resting_cursor_floats_until_idle_hide_and_never_hide_parks() {
        let mut map = empty_map();
        let cursor = placed(&mut map, "sessA");
        cursor.core.motion.idle_hide_ms = 20_000.0;
        assert!(cursor.core.has_resting_motion());
        assert!(map.needs_frame_tick());

        let cursor = map.cursors.get_mut("sessA").unwrap();
        cursor.core.motion.idle_hide_ms = 0.0;
        assert!(!map.needs_frame_tick(), "a never-hiding cursor rests still");
    }

    #[test]
    fn focus_rect_and_reduced_motion_countdown_keep_macos_frames() {
        let mut map = empty_map();
        let cursor = placed(&mut map, "sessA");
        cursor.core.visual.reduced_motion = cursor_overlay::ReducedMotion::On;
        cursor.core.motion.idle_hide_ms = 20_000.0;
        // The macOS loop has no idle deadline, so the opaque countdown ticks.
        assert!(!cursor.core.needs_frame_tick());
        assert!(cursor.needs_frame_tick());

        cursor.core.motion.idle_hide_ms = 0.0;
        assert!(!cursor.needs_frame_tick());
        cursor.apply_command(OverlayCommand::ShowFocusRect(Some([0.0, 0.0, 10.0, 10.0])));
        assert!(cursor.needs_frame_tick());
        for _ in 0..60 {
            cursor.tick(1.0 / 60.0);
        }
        assert!(cursor.focus_rect.is_none());

        cursor.core.idle_alpha = 0.0;
        assert!(!map.needs_frame_tick(), "a fully hidden cursor must park");
    }

    #[test]
    fn per_key_arrival_isolation() {
        // Two concurrent waiters keyed A and B; firing A must not cancel B.
        // This mirrors the ARRIVAL_TX HashMap logic in isolation (no statics).
        let mut waiters: HashMap<CursorKey, tokio::sync::oneshot::Sender<()>> = HashMap::new();
        let (txa, mut rxa) = tokio::sync::oneshot::channel::<()>();
        let (txb, mut rxb) = tokio::sync::oneshot::channel::<()>();
        waiters.insert("A".to_owned(), txa);
        waiters.insert("B".to_owned(), txb);

        // Fire A's arrival.
        if let Some(tx) = waiters.remove("A") {
            let _ = tx.send(());
        }
        // A resolved, B still pending.
        assert!(matches!(rxa.try_recv(), Ok(())));
        assert!(matches!(
            rxb.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
    }
}
