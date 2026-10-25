//! Linux/X11 toplevels that never publish `_NET_WM_PID` (Tk, many Java/AWT
//! builds, Wine, legacy Xlib/Xt clients) must still be addressable by
//! `pid` + `window_id` (#3894).
//!
//! The test process is itself the bare Xlib-style client: it maps a titled
//! toplevel through x11rb without `_NET_WM_PID` or `WM_CLIENT_MACHINE`, so
//! the only way the driver can attribute it is the X-Resource
//! `LocalClientPID` of the connection that created it. The oracles are
//! protocol (`list_windows` reports this process's pid, a pid-filtered list
//! finds the window, and `get_window_state` accepts the pair) and fixture
//! state (the window's own connection receives the ButtonPress of a
//! window-scoped background click).
//!
//! #[ignore] (needs an X11 display with a window manager). Run:
//!   cargo test -p cua-driver-e2e --test x11_unpublished_pid_linux_test -- --ignored --nocapture --test-threads=1

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use cua_driver_testkit::e2e::{
    execute_case, recording_evidence, CaseSpec, Delivery, DriverRoute, Observation, OracleKind,
    Scope, Targeting,
};
use cua_driver_testkit::{Driver, McpDriver};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, WindowClass,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

struct BareClient {
    conn: RustConnection,
    window: u32,
    title: String,
}

impl BareClient {
    fn map() -> Self {
        let (conn, screen_num) =
            RustConnection::connect(None).expect("connect to the X11 display under test");
        let screen = &conn.setup().roots[screen_num];
        let window = conn.generate_id().expect("allocate X11 window id");
        let title = format!("CuaUnpublishedPid-{}", std::process::id());
        conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            window,
            screen.root,
            80,
            80,
            480,
            320,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new()
                .background_pixel(screen.white_pixel)
                .event_mask(
                    EventMask::BUTTON_PRESS | EventMask::BUTTON_RELEASE | EventMask::EXPOSURE,
                ),
        )
        .expect("create bare X11 toplevel");
        conn.change_property8(
            PropMode::REPLACE,
            window,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            title.as_bytes(),
        )
        .expect("set WM_NAME");
        conn.change_property8(
            PropMode::REPLACE,
            window,
            AtomEnum::WM_CLASS,
            AtomEnum::STRING,
            b"cua-unpublished-pid\0CuaUnpublishedPid\0",
        )
        .expect("set WM_CLASS");
        conn.map_window(window).expect("map bare X11 toplevel");
        conn.flush().expect("flush X11 requests");
        Self {
            conn,
            window,
            title,
        }
    }

    /// Precondition: the client really publishes no `_NET_WM_PID`.
    fn publishes_net_wm_pid(&self) -> bool {
        let atom = self
            .conn
            .intern_atom(false, b"_NET_WM_PID")
            .expect("intern _NET_WM_PID")
            .reply()
            .expect("intern _NET_WM_PID reply")
            .atom;
        let reply = self
            .conn
            .get_property(false, self.window, atom, AtomEnum::ANY, 0, 1)
            .expect("read _NET_WM_PID")
            .reply()
            .expect("read _NET_WM_PID reply");
        reply.type_ != x11rb::NONE
    }

    fn drain_button_presses(&self) -> usize {
        let mut presses = 0;
        while let Ok(Some(event)) = self.conn.poll_for_event() {
            if matches!(event, Event::ButtonPress(press) if press.event == self.window) {
                presses += 1;
            }
        }
        presses
    }

    fn button_events(&self) -> Vec<(bool, x11rb::protocol::xproto::ButtonPressEvent)> {
        self.conn.get_input_focus().unwrap().reply().unwrap();
        let mut events = Vec::new();
        while let Some(event) = self.conn.poll_for_event().unwrap() {
            match event {
                Event::ButtonPress(event) => events.push((true, event)),
                Event::ButtonRelease(event) => events.push((false, event)),
                Event::Error(error) => panic!("X11 observer error: {error:?}"),
                _ => {}
            }
        }
        events
    }
}

fn run_native_pixel_scroll(desktop: bool) {
    let cell = if desktop {
        "linux-xlib-native-pixel-scroll-px-desktop"
    } else {
        "linux-xlib-native-pixel-scroll-px-window"
    };
    let case = CaseSpec::delivered(
        cell,
        "x11-bare-client",
        "xlib",
        "native_pixel_scroll",
        Targeting::Px,
        if desktop {
            Delivery::Foreground
        } else {
            Delivery::Background
        },
        if desktop {
            Scope::Desktop
        } else {
            Scope::Window
        },
        if desktop {
            DriverRoute::LinuxXTest
        } else {
            DriverRoute::LinuxXSendEvent
        },
        vec![OracleKind::FixtureState, OracleKind::Protocol],
    );
    execute_case(case, |evidence| {
        let mut driver = McpDriver::spawn_named(cell).expect("source-built pixel scroll driver");
        *evidence = recording_evidence(driver.recording_dir());
        let client = BareClient::map();
        let pid = std::process::id();
        let window = u64::from(client.window);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if listed_record(&mut driver, serde_json::json!({}), window)
                .is_some_and(|record| record["is_on_screen"].as_bool() == Some(true))
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "wheel observer window was not managed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        client
            .conn
            .configure_window(
                client.window,
                &x11rb::protocol::xproto::ConfigureWindowAux::new()
                    .stack_mode(x11rb::protocol::xproto::StackMode::ABOVE),
            )
            .unwrap()
            .check()
            .unwrap();
        let root = client.conn.setup().roots[0].root;
        let absolute = client
            .conn
            .translate_coordinates(client.window, root, 37, 41)
            .unwrap()
            .reply()
            .unwrap();
        client.button_events();
        driver.start_behavior_recording();
        for (pixels, direction, button, detents) in [
            (1, "down", 5, 1),
            (49, "down", 5, 1),
            (149, "down", 5, 1),
            (150, "down", 5, 2),
            (250, "down", 5, 3),
            (800, "down", 5, 8),
            (5001, "down", 5, 50),
            (5100, "down", 5, 51),
            (65535, "down", 5, 655),
            (100, "up", 4, 1),
            (100, "left", 6, 1),
            (100, "right", 7, 1),
        ] {
            let mut args = serde_json::json!({"direction":direction,"pixels":pixels});
            if desktop {
                args["target"] = serde_json::json!({"kind":"desktop","display_id":"primary"});
                args["x"] = absolute.dst_x.into();
                args["y"] = absolute.dst_y.into();
            } else {
                let snapshot = driver.call(
                    "get_window_state",
                    serde_json::json!({
                        "pid":pid,"window_id":window,"include_accessibility_tree":false,
                    }),
                );
                assert!(!snapshot.is_error(), "{}", snapshot.text());
                args["target"] = serde_json::json!({"kind":"window","pid":pid,"window_id":window});
                args["x"] = 37.into();
                args["y"] = 41.into();
            }
            let response = driver.call("scroll", args);
            assert!(
                !response.is_error(),
                "{direction}/{pixels}: {}",
                response.text()
            );
            let public = response.structured();
            assert_eq!(public["effect"], "unverifiable");
            assert_eq!(
                public["route"],
                if desktop {
                    "global_input"
                } else {
                    "synthetic_events"
                }
            );
            assert_eq!(
                public["delivery"]["mode"],
                if desktop { "foreground" } else { "background" }
            );
            assert_eq!(public["delivery"]["delivered_count"], detents);
            let events = client.button_events();
            assert_eq!(events.len(), detents * 2, "{direction}/{pixels}");
            for pair in events.chunks_exact(2) {
                assert!(pair[0].0 && !pair[1].0);
                for (_, event) in pair {
                    assert_eq!(event.event, client.window);
                    assert_eq!(event.detail, button);
                    assert_eq!((event.event_x, event.event_y), (37, 41));
                    assert_eq!(event.response_type & 0x80 != 0, !desktop);
                }
                assert!(pair[1].1.time.wrapping_sub(pair[0].1.time) >= 36);
            }
            if detents >= 8 {
                let pairs: Vec<_> = events.chunks_exact(2).collect();
                let mut gaps: Vec<_> = pairs
                    .windows(2)
                    .map(|pair| pair[1][0].1.time.wrapping_sub(pair[0][1].1.time))
                    .collect();
                gaps.sort_unstable();
                assert!(gaps[gaps.len() / 2] < 36, "inter-detent gaps: {gaps:?}");
            }
        }
        for mut args in [
            serde_json::json!({"pixels":0}),
            serde_json::json!({"pixels":-1}),
            serde_json::json!({"pixels":0.1}),
            serde_json::json!({"pixels":49.5}),
            serde_json::json!({"pixels":149.5}),
            serde_json::json!({"pixels":150.1}),
            serde_json::json!({"pixels":65536}),
            serde_json::json!({"pixels":800,"amount":3}),
            serde_json::json!({"pixels":800,"by":"line"}),
            serde_json::json!({"amount":0}),
            serde_json::json!({"amount":51}),
            serde_json::json!({"amount":1.5}),
        ] {
            args["direction"] = "down".into();
            if desktop {
                args["target"] = serde_json::json!({"kind":"desktop","display_id":"primary"});
                args["x"] = absolute.dst_x.into();
                args["y"] = absolute.dst_y.into();
            } else {
                args["target"] = serde_json::json!({"kind":"window","pid":pid,"window_id":window});
                args["x"] = 37.into();
                args["y"] = 41.into();
            }
            let response = driver.call("scroll", args.clone());
            assert!(
                response.is_error(),
                "invalid distance {args} was accepted: {}",
                response.text()
            );
            assert_eq!(response.structured()["code"], "invalid_arguments");
            assert!(client.button_events().is_empty());
        }
        Observation::delivered_with_fixture_state(vec![OracleKind::Protocol])
    });
}

#[test]
#[ignore = "requires a disposable X11 desktop with XTEST and a window manager"]
fn x11_native_pixel_scroll_public_window_route_matches_raw_events() {
    run_native_pixel_scroll(false);
}

#[test]
#[ignore = "requires a disposable X11 desktop with XTEST and a window manager"]
fn x11_native_pixel_scroll_public_desktop_route_matches_raw_events() {
    run_native_pixel_scroll(true);
}

#[test]
#[ignore = "requires a disposable X11 desktop and a window manager"]
fn x11_native_pixel_scroll_reports_partial_input_when_the_target_disappears() {
    let case = CaseSpec::delivered(
        "linux-xlib-native-pixel-scroll-interrupted",
        "x11-bare-client",
        "xlib",
        "native_pixel_scroll_interrupted",
        Targeting::Px,
        Delivery::Background,
        Scope::Window,
        DriverRoute::LinuxXSendEvent,
        vec![OracleKind::FixtureState, OracleKind::Protocol],
    );
    execute_case(case, |evidence| {
        let mut driver = McpDriver::spawn_named("native-wheel-interruption").unwrap();
        *evidence = recording_evidence(driver.recording_dir());
        let client = BareClient::map();
        let pid = std::process::id();
        let window = u64::from(client.window);
        let deadline = Instant::now() + Duration::from_secs(10);
        while listed_record(&mut driver, serde_json::json!({}), window).is_none() {
            assert!(
                Instant::now() < deadline,
                "interruption fixture was not managed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        driver.start_behavior_recording();
        let snapshot = driver.call(
            "get_window_state",
            serde_json::json!({
                "pid":pid,"window_id":window,"include_accessibility_tree":false,
            }),
        );
        assert!(!snapshot.is_error(), "{}", snapshot.text());
        client.button_events();
        let response = std::thread::scope(|scope| {
            let call = scope.spawn(|| {
                driver.call(
                    "scroll",
                    serde_json::json!({
                        "target":{"kind":"window","pid":pid,"window_id":window},
                        "x":37,"y":41,"direction":"down","pixels":5100,
                    }),
                )
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match client.conn.poll_for_event().unwrap() {
                    Some(Event::ButtonRelease(event)) if event.event == client.window => break,
                    Some(_) => {}
                    None => {
                        assert!(Instant::now() < deadline, "no first wheel detent arrived");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            client
                .conn
                .destroy_window(client.window)
                .unwrap()
                .check()
                .unwrap();
            call.join().unwrap()
        });
        assert!(response.is_error(), "{}", response.text());
        assert_eq!(response.structured()["code"], "input_outcome_unknown");
        assert_eq!(response.structured()["effect"], "partial");
        assert_eq!(response.structured()["delivery"]["mode"], "unknown");
        let completed = response.structured()["delivery"]["delivered_count"]
            .as_u64()
            .unwrap();
        assert!((1..51).contains(&completed), "completed={completed}");
        Observation::delivered_with_fixture_state(vec![OracleKind::Protocol])
    });
}

fn listed_record(
    driver: &mut McpDriver,
    args: serde_json::Value,
    window: u64,
) -> Option<serde_json::Value> {
    driver.call("list_windows", args).structured()["windows"]
        .as_array()?
        .iter()
        .find(|w| w["window_id"].as_u64() == Some(window))
        .cloned()
}

#[test]
#[ignore]
fn x11_toplevel_without_net_wm_pid_is_attributed_and_addressable() {
    if std::env::var_os("DISPLAY").is_none() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        if std::env::var_os("CUA_TEST_REQUIRE_FIXTURES").is_some() {
            panic!("the unpublished-pid X11 case requires a native X11 session");
        }
        eprintln!("[x11-unpublished-pid] not a native X11 session; skipping");
        return;
    }
    let cell_id = "linux-xlib-unpublished-pid-left-click-px-background";
    let case = CaseSpec::delivered(
        cell_id,
        "x11-bare-client",
        "xlib",
        "left_click",
        Targeting::Px,
        Delivery::Background,
        Scope::Window,
        DriverRoute::LinuxXSendEvent,
        vec![OracleKind::FixtureState, OracleKind::Protocol],
    );
    execute_case(case, |evidence| {
        let mut driver = McpDriver::spawn_named(cell_id).expect("start source-built Linux driver");
        *evidence = recording_evidence(driver.recording_dir());
        let client = BareClient::map();
        let own_pid = std::process::id();
        let window = u64::from(client.window);
        assert!(
            !client.publishes_net_wm_pid(),
            "fixture precondition: the bare client must not publish _NET_WM_PID"
        );

        // Unfiltered enumeration must attribute the window to this process.
        let deadline = Instant::now() + Duration::from_secs(10);
        let record = loop {
            if let Some(record) = listed_record(&mut driver, serde_json::json!({}), window) {
                if record["is_on_screen"].as_bool() == Some(true) {
                    break record;
                }
            }
            assert!(
                Instant::now() < deadline,
                "window {window:#x} ({}) never appeared on screen in list_windows",
                client.title
            );
            std::thread::sleep(Duration::from_millis(200));
        };
        assert_eq!(
            record["pid"].as_u64(),
            Some(u64::from(own_pid)),
            "window without _NET_WM_PID was not attributed to its X-Resource owner: {record}"
        );

        // A pid-filtered listing finds it.
        assert!(
            listed_record(&mut driver, serde_json::json!({"pid": own_pid}), window).is_some(),
            "list_windows {{pid: {own_pid}}} omitted window {window:#x}"
        );

        driver.start_behavior_recording();
        // get_window_state accepts the pid + window_id pair.
        let state = driver.call(
            "get_window_state",
            serde_json::json!({"pid": own_pid, "window_id": window}),
        );
        assert!(
            !state.is_error(),
            "get_window_state refused the attributed window: {}",
            state.text()
        );
        let width = state.structured()["screenshot_width"]
            .as_f64()
            .unwrap_or(0.0);
        let height = state.structured()["screenshot_height"]
            .as_f64()
            .unwrap_or(0.0);
        assert!(
            width > 0.0 && height > 0.0,
            "get_window_state returned no screenshot geometry: {}",
            state.text()
        );

        // A window-scoped background click reaches the window's own connection.
        client.drain_button_presses();
        let clicked = driver.call(
            "click",
            serde_json::json!({
                "pid": own_pid,
                "window_id": window,
                "x": width / 2.0,
                "y": height / 2.0,
                "delivery_mode": "background"
            }),
        );
        assert!(
            !clicked.is_error(),
            "window-scoped click on the attributed window failed: {}",
            clicked.text()
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut presses = 0;
        while presses == 0 && Instant::now() < deadline {
            presses += client.drain_button_presses();
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            presses > 0,
            "the bare client received no ButtonPress from the window-scoped click: {}",
            clicked.text()
        );
        Observation::delivered_with_fixture_state(vec![OracleKind::Protocol])
    });
}
