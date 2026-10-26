//! Background input synthesis for macOS.
//!
//! Two strategies:
//! 1. **AX action** (`element_index` path): `AXUIElementPerformAction` — pure
//!    RPC, works on hidden/backgrounded windows, no cursor move, no focus steal.
//! 2. **CGEvent / SkyLight** (`x, y` path): synthesize CGEvents and post them
//!    to the target pid. Prefers `SLEventPostToPid` (SkyLight SPI) over the
//!    public `CGEventPostToPid` to reach Catalyst/Chromium apps and trigger
//!    the activity-monitor tickle required for live-input detection.

pub mod ax_actions;
pub mod electron_drag;
pub mod hover;
pub mod interactive;
pub mod keyboard;
pub mod mouse;
pub mod page_scroll;
pub mod pointer_toolkit;
pub mod skylight;

pub use ax_actions::perform_ax_action;
pub use interactive::{
    GesturePhase, InteractiveDeliveryMode, InteractiveInputBatch, InteractiveInputConfig,
    InteractiveInputError, InteractiveInputEvent, InteractiveInputReceipt, InteractiveInputSession,
    KeyState, Modifier, PointerButton, PointerPhase,
};
pub use keyboard::{hotkey, press_key, type_text};
pub use mouse::click_at_xy;

/// Set a retained event's screen location without posting it.
pub(crate) fn set_event_location(
    event: &core_graphics::event::CGEvent,
    location: core_graphics::geometry::CGPoint,
) {
    use foreign_types::ForeignType;
    // SAFETY: CGEvent retains the native event. The SDK takes CGPoint by value.
    unsafe { CGEventSetLocation(event.as_ptr(), location) };
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGEventSetLocation(
        event: core_graphics::sys::CGEventRef,
        location: core_graphics::geometry::CGPoint,
    );
}
