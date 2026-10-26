// SPDX-License-Identifier: MIT

//! Native selectors are data, resolved afresh beneath the selected window.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use atspi::proxy::action::ActionProxy;

use super::*;
use crate::input::native_element::{
    NativeElementClickFailure, NativeElementClickRequest, NativeElementDelivery,
    NativeElementTransport,
};
use crate::input::native_window::NativeClickButton;

const NOT_MEMBER: &str = "element is not in this window's AT-SPI tree; refresh get_window_state()";
const SEARCH_LIMIT: &str = "AT-SPI element search exceeded its tree limit";

/// A checkpoint never grants authority. It only shortens already admitted work.
pub(super) fn check(session_id: Option<&str>) -> Result<()> {
    if let Some(reason) = super::super::native_observation::current()
        .and_then(|observation| observation.stop_reason())
    {
        bail!(reason);
    }
    if session_id.is_some_and(cua_driver_core::session::is_session_ending) {
        bail!("native element click invocation was cancelled");
    }
    Ok(())
}

async fn checked<T, E: std::fmt::Display>(
    session_id: &str,
    future: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    check(Some(session_id))?;
    let result = call(future).await;
    check(Some(session_id))?;
    match result {
        Some(Ok(value)) => Ok(value),
        Some(Err(error)) => Err(anyhow!("{error}")),
        None => bail!("AT-SPI element lookup did not answer in time"),
    }
}

struct SelectedWindow {
    root: RawObjectRef,
    window: crate::x11::WindowInfo,
}

async fn selected_window(
    conn: &AccessibilityConnection,
    request: &NativeElementClickRequest,
    session_id: &str,
) -> Result<SelectedWindow> {
    check(Some(session_id))?;
    let (pid, xid) = (request.pid, u64::from(request.window_id));
    let window = bounded_blocking(move || {
        if pid == 0
            || xid == 0
            || !crate::proc_fs::is_process_live(pid)
            || !crate::x11::window_belongs_to_pid(xid, pid)
        {
            return None;
        }
        crate::x11::window_info(xid)
    })
    .await
    .flatten();
    check(Some(session_id))?;
    let window = window.context("native element window owner is unavailable")?;
    let resolved = resolve_app_for_pid(conn, pid).await?;
    check(Some(session_id))?;
    if resolved.is_none()
        && super::super::native_observation::current()
            .and_then(|observation| observation.incomplete_reason())
            .is_some()
    {
        bail!("AT-SPI application lookup did not complete");
    }
    let ResolvedApp { app, children } =
        resolved.context("window has no AT-SPI accessibility tree")?;
    let seeds = match children {
        Some(children) => children,
        None => checked(session_id, app.get_children()).await?,
    };
    let seeds: Vec<_> = seeds.iter().filter_map(RawObjectRef::from_atspi).collect();
    let frame = resolve_window_frame(conn, pid, xid, &seeds).await;
    check(Some(session_id))?;
    let frame = frame.context("native element window identity is unproven")?;
    let root = seeds
        .into_iter()
        .nth(frame)
        .context("window has no AT-SPI accessibility tree")?;
    Ok(SelectedWindow { root, window })
}

struct Located {
    object: RawObjectRef,
    ancestors: Vec<RawObjectRef>,
}

#[derive(Clone, Copy)]
enum Search {
    Ordinary,
    VisibleTables,
}

/// The same pre-order stack and admission counter as observation, without
/// reading/rendering a rich snapshot before comparing the native identity.
async fn find(
    conn: &AccessibilityConnection,
    root: &RawObjectRef,
    selector: Option<&str>,
    search: Search,
    session_id: &str,
) -> Result<Option<Located>> {
    let mut traversal = traversal::Traversal::lookup(root.clone(), 0);
    let mut budget = VisitBudget::Admitted(super::super::native_observation::MAX_NODE_ATTEMPTS);
    while let Some((object, depth, _, frame)) = traversal.pop() {
        check(Some(session_id))?;
        if depth > super::super::native_observation::MAX_DEPTH || !budget.admit() {
            bail!(SEARCH_LIMIT);
        }
        // Admission precedes matching, including the root and failed reads.
        if matches!(search, Search::Ordinary)
            && selector
                == Some(super::super::native_ax::native_id(&object.name, &object.path).as_str())
        {
            let mut ancestors = traversal.path().to_vec();
            ancestors.pop();
            return Ok(Some(Located { object, ancestors }));
        }
        let children = match search {
            Search::Ordinary => checked(session_id, raw_children(conn.connection(), &object))
                .await?
                .into_iter()
                .map(|object| (object, false))
                .collect::<Vec<_>>(),
            Search::VisibleTables => {
                let children = super::visible_table::children(
                    conn,
                    &object,
                    budget.remaining(),
                    Some(session_id),
                )
                .await?;
                if children.sampled {
                    // Cells are admitted once at child depth and compared
                    // directly. They are never recursively expanded here.
                    if depth >= super::super::native_observation::MAX_DEPTH {
                        continue;
                    }
                    for object in children.objects {
                        check(Some(session_id))?;
                        if !budget.admit() {
                            bail!(SEARCH_LIMIT);
                        }
                        if selector
                            == Some(
                                super::super::native_ax::native_id(&object.name, &object.path)
                                    .as_str(),
                            )
                        {
                            return Ok(Some(Located {
                                object,
                                ancestors: traversal.path().to_vec(),
                            }));
                        }
                    }
                    continue;
                }
                children
                    .objects
                    .into_iter()
                    .map(|object| (object, false))
                    .collect()
            }
        };
        for (child, in_web) in children.into_iter().rev() {
            traversal.push((child, depth + 1, in_web, frame));
        }
    }
    Ok(None)
}

async fn locate(
    conn: &AccessibilityConnection,
    root: &RawObjectRef,
    selector: Option<&str>,
    session_id: &str,
) -> Result<Located> {
    if let Some(found) = find(conn, root, selector, Search::Ordinary, session_id).await? {
        return Ok(found);
    }
    // Only a genuine exhausted-tree miss reaches the separately budgeted pass.
    find(conn, root, selector, Search::VisibleTables, session_id)
        .await?
        .ok_or_else(|| anyhow!(NOT_MEMBER))
}

async fn pin(
    conn: &AccessibilityConnection,
    located: Located,
    session_id: &str,
) -> Result<Located> {
    let mut owners = HashMap::new();
    check(Some(session_id))?;
    let object = identity_ref(conn, &located.object, &mut owners).await;
    check(Some(session_id))?;
    let object = object.context("native element bus identity is unavailable")?;
    let mut ancestors = Vec::with_capacity(located.ancestors.len());
    for ancestor in located.ancestors {
        check(Some(session_id))?;
        let identity = identity_ref(conn, &ancestor, &mut owners).await;
        check(Some(session_id))?;
        ancestors.push(identity.context("native element ancestor identity is unavailable")?);
    }
    check(Some(session_id))?;
    Ok(Located { object, ancestors })
}

async fn action_proxy<'conn>(
    conn: &'conn AccessibilityConnection,
    object: &RawObjectRef,
    session_id: &str,
) -> Result<ActionProxy<'conn>> {
    checked(
        session_id,
        ActionProxy::builder(conn.connection())
            .cache_properties(atspi::zbus::proxy::CacheProperties::No)
            .destination(object.name.clone())?
            .path(object.path.clone())?
            .build(),
    )
    .await
}

fn failure(
    error: anyhow::Error,
    dispatched: bool,
    transport: NativeElementTransport,
) -> NativeElementClickFailure {
    NativeElementClickFailure {
        error,
        dispatched,
        transport,
    }
}

async fn dispatch_action(
    proxy: &ActionProxy<'_>,
    index: usize,
    request: &NativeElementClickRequest,
    session_id: &str,
) -> std::result::Result<NativeElementDelivery, NativeElementClickFailure> {
    let transport = NativeElementTransport::Accessibility;
    verify_owner(request, session_id)
        .await
        .map_err(|error| failure(error, false, transport))?;
    let index = i32::try_from(index).map_err(|error| failure(error.into(), false, transport))?;
    check(Some(session_id)).map_err(|error| failure(error, false, transport))?;
    // Once the RPC is tried, cancellation/timeout cannot justify another route.
    match call(proxy.do_action(index)).await {
        Some(Ok(true)) => Ok(NativeElementDelivery::Accessibility {
            unacknowledged: false,
        }),
        Some(Ok(false)) => Err(failure(
            anyhow!("AT-SPI element refused action {index}"),
            true,
            transport,
        )),
        Some(Err(error)) => Err(failure(error.into(), true, transport)),
        None => Ok(NativeElementDelivery::Accessibility {
            unacknowledged: true,
        }),
    }
}

async fn verify_owner(request: &NativeElementClickRequest, session_id: &str) -> Result<()> {
    check(Some(session_id))?;
    let (pid, xid) = (request.pid, u64::from(request.window_id));
    let proven = bounded_blocking(move || crate::x11::window_belongs_to_pid(xid, pid)).await;
    check(Some(session_id))?;
    if proven != Some(true) {
        bail!("native element window owner is unavailable");
    }
    Ok(())
}

fn context_action<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<usize> {
    let mut matches = names.into_iter().enumerate().filter_map(|(index, name)| {
        name.eq_ignore_ascii_case("showcontextmenu")
            .then_some(index)
    });
    let index = matches.next()?;
    matches.next().is_none().then_some(index)
}

async fn click(
    request: &NativeElementClickRequest,
    session_id: &str,
) -> std::result::Result<NativeElementDelivery, NativeElementClickFailure> {
    let initial = if request.button == NativeClickButton::Right {
        NativeElementTransport::PhysicalPointer
    } else {
        NativeElementTransport::Accessibility
    };
    let prepare = async {
        check(Some(session_id))?;
        request.validate_options()?;
        if crate::wayland::is_wayland() {
            bail!(super::super::native_observation::X11_ROUTE_REQUIRED);
        }
        if super::super::native_observation::for_window(request.pid, u64::from(request.window_id))?
            .is_none()
        {
            bail!("native element click requires its scoped lookup context");
        }
        if request
            .element_id
            .as_deref()
            .is_some_and(|id| id.starts_with("x11:"))
        {
            bail!("element actions require AT-SPI; X11 fallback IDs only identify windows");
        }
        let conn = checked(session_id, shared_connection()).await?;
        let selected = selected_window(conn, request, session_id).await?;
        let located = pin(
            conn,
            locate(
                conn,
                &selected.root,
                request.element_id.as_deref(),
                session_id,
            )
            .await?,
            session_id,
        )
        .await?;
        Ok::<_, anyhow::Error>((conn, selected, located))
    }
    .await
    .map_err(|error| failure(error, false, initial))?;
    let (conn, selected, located) = prepare;
    if request.button == NativeClickButton::Left {
        let proxy = action_proxy(conn, &located.object, session_id)
            .await
            .map_err(|error| failure(error, false, initial))?;
        let actions = checked(session_id, proxy.get_actions())
            .await
            .map_err(|error| failure(error, false, initial))?;
        if actions.is_empty() {
            return Err(failure(
                anyhow!("element has no primary accessibility action"),
                false,
                initial,
            ));
        }
        return dispatch_action(&proxy, 0, request, session_id).await;
    }
    let position = super::element_position::position(
        conn,
        &located.object,
        &located.ancestors,
        &selected.window,
        session_id,
    )
    .await;
    match position {
        Ok([x, y]) => {
            verify_owner(request, session_id)
                .await
                .map_err(|error| failure(error, false, initial))?;
            check(Some(session_id)).map_err(|error| failure(error, false, initial))?;
            // Existing XTest primitive preserves the press/release pair. Its
            // outcome is final; an error must never trigger a second actuator.
            crate::input::send_native_element_click_xtest([x, y], || check(Some(session_id)))
                .map(|()| NativeElementDelivery::PhysicalPointer)
                .map_err(|error| failure(error.error, error.dispatched, initial))
        }
        Err(preparation_error) => {
            check(Some(session_id)).map_err(|error| failure(error, false, initial))?;
            // Original right-click fallback repeats membership after positional
            // preparation fails. Action enumeration failure keeps that error.
            let fallback = async {
                let selected = selected_window(conn, request, session_id).await?;
                let located = pin(
                    conn,
                    locate(
                        conn,
                        &selected.root,
                        request.element_id.as_deref(),
                        session_id,
                    )
                    .await?,
                    session_id,
                )
                .await?;
                let proxy = action_proxy(conn, &located.object, session_id).await?;
                let actions = checked(session_id, proxy.get_actions()).await?;
                let index = context_action(actions.iter().map(|action| action.name.as_str()));
                Ok::<_, anyhow::Error>((proxy, index))
            }
            .await;
            check(Some(session_id)).map_err(|error| failure(error, false, initial))?;
            match fallback {
                Ok((proxy, Some(index))) => {
                    dispatch_action(&proxy, index, request, session_id).await
                }
                _ => Err(failure(preparation_error, false, initial)),
            }
        }
    }
}

pub(crate) fn click_native_element(
    request: &NativeElementClickRequest,
    observation: super::super::native_observation::Observation,
    session_id: &str,
) -> std::result::Result<NativeElementDelivery, NativeElementClickFailure> {
    runtime().block_on(observation.scope(click(request, session_id)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_menu_fallback_requires_one_exact_ascii_case_insensitive_action() {
        assert_eq!(context_action(["click", "ShowContextMenu"]), Some(1));
        assert_eq!(context_action(["showcontextmenu", "SHOWCONTEXTMENU"]), None);
        assert_eq!(
            context_action(["show context menu", "showcontextmenu "]),
            None
        );
        assert_eq!(context_action([]), None);
    }
}
