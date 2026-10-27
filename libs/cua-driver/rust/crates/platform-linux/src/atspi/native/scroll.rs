// SPDX-License-Identifier: MIT

//! App-originated native element scrolling on the admitted X11 worker.
//!
//! Lookup reuses the click path's fresh selected-window traversal. The native
//! focus lifetime starts only after membership succeeds, and preparation errors
//! retain the focus phase separately from wheel-pair completion.

use anyhow::{bail, Context, Result};

use super::{element, element_position, runtime, shared_connection};
use crate::atspi::native_observation::{self, Observation};
use crate::input::native_element::NativeElementScrollRequest;
use crate::input::native_window::{
    with_native_window_focus, NativeWindowCancellation, NativeWindowOutcome,
    NativeWindowSetupFailure, NativeWindowTarget,
};

/// Run only on the existing admitted blocking worker, outside a Tokio runtime.
/// The caller owns the operation lease and the observation's cancellation scope.
pub(crate) fn scroll_native_element(
    request: &NativeElementScrollRequest,
    observation: Observation,
    session_id: &str,
) -> std::result::Result<NativeWindowOutcome<(), anyhow::Error>, NativeWindowSetupFailure> {
    let target = NativeWindowTarget {
        pid: request.pid,
        window_id: request.window_id,
    };
    let prepared = runtime().block_on(observation.scope(async {
        element::check(Some(session_id))?;
        native_observation::for_window(request.pid, u64::from(request.window_id))?
            .context("native element scroll requires its scoped lookup context")?;
        if request.element_id.starts_with("x11:") {
            bail!("element actions require AT-SPI; X11 fallback IDs only identify windows");
        }
        let conn = element::checked(session_id, shared_connection()).await?;
        let selected = element::selected_window(conn, target, session_id).await?;
        let mut located = element::locate(
            conn,
            &selected.root,
            Some(request.element_id.as_str()),
            session_id,
        )
        .await?;
        // The scroll branch receives no ancestor vector. Keep membership's
        // selected object while avoiding unrelated ancestor identity reads.
        located.ancestors.clear();
        let located = element::pin(conn, located, session_id).await?;
        Ok::<_, anyhow::Error>((conn, located.object))
    }));
    let (conn, object) = prepared.map_err(NativeWindowSetupFailure::no_input)?;
    let cancellation =
        NativeWindowCancellation::from_observation(session_id.to_owned(), observation.clone());
    with_native_window_focus(target, cancellation, |x11, context| -> Result<()> {
        context.check()?;
        let point = runtime().block_on(observation.scope(element_position::scroll_position(
            conn,
            &object,
            request.window_id,
            session_id,
        )))?;
        // Original element pixels validation follows position preparation.
        // Keep its error text local; the coordinate profile has its own boundary.
        if request.pixels == 0 {
            bail!("pixels must be non-zero");
        }
        // Root-to-client wire translation remains in the shared event resolver.
        context.scroll_at_root(x11, point, request.direction, request.pixels)
    })
}
