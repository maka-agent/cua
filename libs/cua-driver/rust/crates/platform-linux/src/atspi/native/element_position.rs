// SPDX-License-Identifier: MIT

//! Live screen geometry for native element pointer preparation.

use anyhow::{bail, Context, Result};
use atspi::State;
use atspi_connection::AccessibilityConnection;

use super::visible_table::{bounds, Rect};
use super::{accessible_for, call, RawObjectRef};
use crate::x11::WindowInfo;

fn intersect(left: Rect, right: Rect) -> Rect {
    Rect {
        left: left.left.max(right.left),
        top: left.top.max(right.top),
        right: left.right.min(right.right),
        bottom: left.bottom.min(right.bottom),
    }
}

fn window_rect(window: &WindowInfo) -> Rect {
    Rect {
        left: i64::from(window.x),
        top: i64::from(window.y),
        right: i64::from(window.x) + i64::from(window.width),
        bottom: i64::from(window.y) + i64::from(window.height),
    }
}

fn center(rect: Rect) -> Result<[i16; 2]> {
    let width = rect.right - rect.left;
    let height = rect.bottom - rect.top;
    if width <= 0 || height <= 0 {
        bail!("element has no visible bounds in this window");
    }
    Ok([
        i16::try_from(rect.left + width / 2)?,
        i16::try_from(rect.top + height / 2)?,
    ])
}

/// Resolve an absolute screen point without activating or scrolling the element.
/// `ancestors` contains the root-to-parent chain, excluding `target`.
pub(super) async fn position(
    conn: &AccessibilityConnection,
    target: &RawObjectRef,
    ancestors: &[RawObjectRef],
    window_id: u32,
    session_id: &str,
) -> Result<[i16; 2]> {
    super::element::check(Some(session_id))?;
    let accessible = call(accessible_for(conn, target)).await;
    super::element::check(Some(session_id))?;
    let accessible = accessible.context("AT-SPI element access timed out")??;

    super::element::check(Some(session_id))?;
    let states = call(accessible.get_state()).await;
    super::element::check(Some(session_id))?;
    let states = states.context("AT-SPI element state query timed out")??;
    if !states.contains(State::Showing) || !states.contains(State::Visible) {
        bail!("element is not visible; scroll it into view before right-clicking");
    }

    let mut visible = live_window_clip(conn, target, window_id, session_id).await?;

    for ancestor in ancestors {
        super::element::check(Some(session_id))?;
        let accessible = call(accessible_for(conn, ancestor)).await;
        super::element::check(Some(session_id))?;
        let accessible = accessible.context("AT-SPI ancestor access timed out")??;

        super::element::check(Some(session_id))?;
        let role = call(accessible.get_role_name()).await;
        super::element::check(Some(session_id))?;
        let role = role.context("AT-SPI ancestor did not return a role")??;
        if matches!(role.as_str(), "viewport" | "scroll pane") {
            super::element::check(Some(session_id))?;
            let ancestor_bounds = bounds(conn, ancestor, Some(session_id)).await;
            super::element::check(Some(session_id))?;
            visible = intersect(visible, ancestor_bounds?);
        }
    }

    center(visible)
}

async fn live_window_clip(
    conn: &AccessibilityConnection,
    target: &RawObjectRef,
    window_id: u32,
    session_id: &str,
) -> Result<Rect> {
    super::element::check(Some(session_id))?;
    let target_bounds = bounds(conn, target, Some(session_id)).await?;
    super::element::check(Some(session_id))?;
    let window = super::bounded_blocking(move || crate::x11::window_info(u64::from(window_id)))
        .await
        .flatten();
    super::element::check(Some(session_id))?;
    let window = window.context("native element position window is unavailable")?;
    Ok(intersect(target_bounds, window_rect(&window)))
}

/// A scroll target uses only its own Screen bounds and the live window.
/// The focus context already exists when this function is entered.
pub(super) async fn scroll_position(
    conn: &AccessibilityConnection,
    target: &RawObjectRef,
    window_id: u32,
    session_id: &str,
) -> Result<[i16; 2]> {
    center(live_window_clip(conn, target, window_id, session_id).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midpoint_uses_only_bounds_remaining_inside_the_window_and_scroll_ancestor() {
        let target = Rect {
            left: 70,
            top: 90,
            right: 170,
            bottom: 190,
        };
        let window = Rect {
            left: 100,
            top: 100,
            right: 300,
            bottom: 250,
        };
        let viewport = Rect {
            left: 110,
            top: 120,
            right: 151,
            bottom: 161,
        };
        assert_eq!(
            center(intersect(intersect(target, window), viewport))
                .expect("the element has visible clipped bounds"),
            [130, 140],
        );
    }

    #[test]
    fn empty_intersection_refuses_and_screen_midpoint_must_fit_i16() {
        let empty = Rect {
            left: 10,
            top: 20,
            right: 10,
            bottom: 30,
        };
        assert_eq!(
            center(empty)
                .expect_err("an empty visible rectangle cannot receive input")
                .to_string(),
            "element has no visible bounds in this window",
        );
        let negative_odd = Rect {
            left: -5,
            top: -7,
            right: 0,
            bottom: -2,
        };
        assert_eq!(
            center(negative_odd).expect("negative screen coordinates still fit i16"),
            [-3, -5],
        );
        let out_of_range = center(Rect {
            left: i64::from(i16::MAX),
            top: 0,
            right: i64::from(i16::MAX) + 2,
            bottom: 2,
        })
        .expect_err("a midpoint outside i16 must not wrap");
        assert!(out_of_range.is::<std::num::TryFromIntError>());
    }
}
