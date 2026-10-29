// SPDX-License-Identifier: MIT

//! App-originated native element scrolling on the admitted X11 worker.
//!
//! Lookup reuses the click path's fresh selected-window traversal. The native
//! focus lifetime starts only after membership succeeds, and preparation errors
//! retain the focus phase separately from wheel-pair completion.

use anyhow::{Context, Result, bail};

use super::{element, element_position, runtime, shared_connection};
use crate::atspi::native_observation::{self, Observation};
use crate::input::native_element::NativeElementScrollRequest;
use crate::input::native_window::{
    NativeWindowCancellation, NativeWindowContext, NativeWindowOutcome, NativeWindowSetupFailure,
    NativeWindowTarget, with_native_window_focus,
};

pub(crate) struct PreparedNativeScroll {
    conn: &'static atspi_connection::AccessibilityConnection,
    object: super::RawObjectRef,
    target: NativeWindowTarget,
}

async fn prepare(
    target: NativeWindowTarget,
    selector: &str,
    session_id: &str,
    check: &dyn Fn() -> Result<()>,
) -> Result<PreparedNativeScroll> {
    check()?;
    if selector.starts_with("x11:") {
        bail!("element actions require AT-SPI; X11 fallback IDs only identify windows");
    }
    let conn = element::checked(session_id, shared_connection()).await?;
    check()?;
    let selected = element::selected_window(conn, target, session_id).await?;
    check()?;
    let mut located = element::locate(conn, &selected.root, Some(selector), session_id).await?;
    check()?;
    // Source scroll receives no ancestor vector. Keep the member without
    // reading unrelated ancestor identities, just like the existing App route.
    located.ancestors.clear();
    let located = element::pin(conn, located, session_id).await?;
    check()?;
    Ok(PreparedNativeScroll {
        conn,
        object: located.object,
        target,
    })
}

pub(crate) fn prepare_native_scroll(
    target: NativeWindowTarget,
    selector: &str,
    session_id: &str,
    check: &dyn Fn() -> Result<()>,
) -> Result<PreparedNativeScroll> {
    runtime().block_on(prepare(target, selector, session_id, check))
}

impl PreparedNativeScroll {
    async fn position(&self, session_id: &str) -> Result<[i16; 2]> {
        element_position::scroll_position(
            self.conn,
            &self.object,
            self.target.window_id,
            session_id,
        )
        .await
    }

    pub(crate) fn position_owned(&self, context: &NativeWindowContext) -> Result<[i16; 2]> {
        context.check()?;
        let point = runtime().block_on(element_position::native_scroll_position(
            self.conn,
            &self.object,
            self.target.window_id,
            context.session_id(),
        ))?;
        context.check()?;
        Ok(point)
    }
}

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
        prepare(target, &request.element_id, session_id, &|| {
            element::check(Some(session_id))
        })
        .await
    }));
    let prepared = prepared.map_err(NativeWindowSetupFailure::no_input)?;
    let cancellation =
        NativeWindowCancellation::from_observation(session_id.to_owned(), observation.clone());
    with_native_window_focus(target, cancellation, |x11, context| -> Result<()> {
        context.check()?;
        let point = runtime().block_on(observation.scope(prepared.position(session_id)))?;
        // Original element pixels validation follows position preparation.
        // Keep its error text local; the coordinate profile has its own boundary.
        if request.pixels == 0 {
            bail!("pixels must be non-zero");
        }
        // Root-to-client wire translation remains in the shared event resolver.
        context.scroll_at_root(x11, point, request.direction, request.pixels)
    })
}
