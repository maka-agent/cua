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
use crate::input::native_window::{
    with_native_window_focus, NativeClickButton, NativeWindowCancellation, NativeWindowTarget,
};

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

pub(super) async fn checked<T, E: std::fmt::Display>(
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

pub(super) struct SelectedWindow {
    pub(super) root: RawObjectRef,
}

pub(super) async fn selected_window(
    conn: &AccessibilityConnection,
    target: NativeWindowTarget,
    session_id: &str,
) -> Result<SelectedWindow> {
    check(Some(session_id))?;
    let (pid, xid) = (target.pid, u64::from(target.window_id));
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
    window.context("native element window owner is unavailable")?;
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
    Ok(SelectedWindow { root })
}

pub(super) struct Located {
    pub(super) object: RawObjectRef,
    pub(super) ancestors: Vec<RawObjectRef>,
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

pub(super) async fn locate(
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

pub(super) async fn pin(
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
    let accessible = checked(session_id, accessible_via_bus(conn, object)).await?;
    // Read the interface names verbatim: a provider may advertise interfaces
    // unknown to the atspi crate alongside the standard Action interface.
    let interfaces: Vec<String> =
        checked(session_id, accessible.inner().call("GetInterfaces", &())).await?;
    if !interfaces
        .iter()
        .any(|name| name == "org.a11y.atspi.Action")
    {
        bail!("AT-SPI element does not implement Action");
    }
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

/// Native tool results render `Display`, so preserve the action reader's
/// public cause-chain text here without flattening away its typed source.
#[derive(Debug)]
struct ActionReadError(anyhow::Error);

impl std::fmt::Display for ActionReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "AT-SPI element does not expose actions; refresh get_window_state(): {:#}",
            self.0
        )
    }
}

impl std::error::Error for ActionReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
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
            anyhow!("AT-SPI element refused action {index}; refresh get_window_state() to check its state"),
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

fn click_target(request: &NativeElementClickRequest) -> NativeWindowTarget {
    NativeWindowTarget {
        pid: request.pid,
        window_id: request.window_id,
    }
}

/// The shared context can attempt focus or pointer input before returning an
/// error. Preserve an already-attempted accessibility actuator's error/route.
fn after_window_input(
    mut failure: NativeElementClickFailure,
    window_input_attempted: bool,
) -> NativeElementClickFailure {
    if !failure.dispatched && window_input_attempted {
        failure.dispatched = true;
        failure.transport = NativeElementTransport::WindowSendEvent;
    }
    failure
}

fn check_retained(
    observation: &super::super::native_observation::Observation,
    session_id: &str,
) -> Result<()> {
    if let Some(reason) = observation.stop_reason() {
        bail!(reason);
    }
    check(Some(session_id))
}

async fn lookup(
    conn: &AccessibilityConnection,
    request: &NativeElementClickRequest,
    session_id: &str,
) -> Result<Located> {
    let selected = selected_window(conn, click_target(request), session_id).await?;
    pin(
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
    .await
}

async fn prepare(
    request: &NativeElementClickRequest,
    session_id: &str,
) -> Result<(&'static AccessibilityConnection, Located)> {
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
    let located = lookup(conn, request, session_id).await?;
    Ok((conn, located))
}

/// ReadActions has already succeeded before entering this target lifetime.
fn dispatch_action_with_focus(
    proxy: &ActionProxy<'_>,
    index: usize,
    request: &NativeElementClickRequest,
    observation: &super::super::native_observation::Observation,
    session_id: &str,
    previous_window_input_attempted: bool,
) -> std::result::Result<NativeElementDelivery, NativeElementClickFailure> {
    let transport = NativeElementTransport::Accessibility;
    let outcome = with_native_window_focus(
        click_target(request),
        NativeWindowCancellation::from_observation(session_id.to_owned(), observation.clone()),
        |_, context| {
            context
                .check()
                .map_err(|error| failure(error.into(), false, transport))?;
            runtime()
                .block_on(observation.scope(dispatch_action(proxy, index, request, session_id)))
        },
    );
    match outcome {
        Ok(outcome) => outcome.result.map_err(|error| {
            after_window_input(
                error,
                previous_window_input_attempted || outcome.phase.input_attempted,
            )
        }),
        Err(error) => Err(after_window_input(
            failure(error.error, false, transport),
            previous_window_input_attempted || error.phase.input_attempted,
        )),
    }
}

/// Positional/setup errors may take the original context-action fallback.
/// Once the selected-window click helper is entered its result is final,
/// including an error from its first move before any button edge.
enum RightClickFailure {
    Preparation(anyhow::Error),
    Final(NativeElementClickFailure),
}

pub(crate) fn click_native_element(
    request: &NativeElementClickRequest,
    observation: super::super::native_observation::Observation,
    session_id: &str,
) -> std::result::Result<NativeElementDelivery, NativeElementClickFailure> {
    let initial = if request.button == NativeClickButton::Right {
        NativeElementTransport::WindowSendEvent
    } else {
        NativeElementTransport::Accessibility
    };
    // The input worker, rather than an async runtime frame, owns the focus
    // lifetime. Each AT-SPI phase enters the same existing runtime separately.
    let (conn, located) = runtime()
        .block_on(observation.scope(prepare(request, session_id)))
        .map_err(|error| failure(error, false, initial))?;
    if request.button == NativeClickButton::Left {
        let read = runtime().block_on(observation.scope(async {
            let proxy = action_proxy(conn, &located.object, session_id).await?;
            let actions = super::native_action_names(&proxy, Some(session_id)).await?;
            Ok::<_, anyhow::Error>((proxy, actions))
        }));
        // A stopped invocation keeps its stop reason. Only an ordinary reader
        // failure receives the original action-reader context.
        check_retained(&observation, session_id).map_err(|error| failure(error, false, initial))?;
        let (proxy, actions) =
            read.map_err(|error| failure(ActionReadError(error).into(), false, initial))?;
        if actions.is_empty() {
            return Err(failure(
                anyhow!("element has no primary accessibility action"),
                false,
                initial,
            ));
        }
        return dispatch_action_with_focus(&proxy, 0, request, &observation, session_id, false);
    }

    let window_click = with_native_window_focus(
        click_target(request),
        NativeWindowCancellation::from_observation(session_id.to_owned(), observation.clone()),
        |x11, context| {
            let final_failure = |error| RightClickFailure::Final(failure(error, false, initial));
            context
                .check()
                .map_err(|error| final_failure(error.into()))?;
            let position =
                runtime().block_on(observation.scope(super::element_position::position(
                    conn,
                    &located.object,
                    &located.ancestors,
                    request.window_id,
                    session_id,
                )));
            // A stopped caller never starts fallback, including a stop that
            // happened while a failing position RPC was in flight.
            context
                .check()
                .map_err(|error| final_failure(error.into()))?;
            let [x, y] = position.map_err(RightClickFailure::Preparation)?;
            runtime()
                .block_on(observation.scope(verify_owner(request, session_id)))
                .map_err(final_failure)?;
            context
                .check()
                .map_err(|error| final_failure(error.into()))?;
            context
                .click_at_root(x11, [x, y], request.button, request.count)
                .map(|()| NativeElementDelivery::WindowSendEvent)
                .map_err(|error| RightClickFailure::Final(failure(error, false, initial)))
        },
    );
    // Returning from the shared lifetime completes release/100ms/FocusOut
    // before any fallback lookup, ReadActions or second target construction.
    let (preparation_error, previous_window_input_attempted) = match window_click {
        Ok(outcome) => match outcome.result {
            Ok(delivery) => return Ok(delivery),
            Err(RightClickFailure::Final(error)) => {
                return Err(after_window_input(error, outcome.phase.input_attempted));
            }
            Err(RightClickFailure::Preparation(error)) => (error, outcome.phase.input_attempted),
        },
        // Original target-constructor errors join the positional fallback too.
        Err(error) => (error.error, error.phase.input_attempted),
    };
    check_retained(&observation, session_id).map_err(|error| {
        after_window_input(
            failure(error, false, initial),
            previous_window_input_attempted,
        )
    })?;
    let fallback = runtime().block_on(observation.scope(async {
        // Membership failures replace the primary positional/setup error.
        let located = lookup(conn, request, session_id).await?;
        // Failure to read a context action preserves that primary error.
        let proxy = match action_proxy(conn, &located.object, session_id).await {
            Ok(proxy) => proxy,
            Err(_) => return Ok(None),
        };
        let actions = match super::native_action_names(&proxy, Some(session_id)).await {
            Ok(actions) => actions,
            Err(_) => return Ok(None),
        };
        let index = context_action(actions.iter().map(String::as_str));
        Ok::<_, anyhow::Error>(Some((proxy, index)))
    }));
    check_retained(&observation, session_id).map_err(|error| {
        after_window_input(
            failure(error, false, initial),
            previous_window_input_attempted,
        )
    })?;
    match fallback {
        Err(error) => Err(after_window_input(
            failure(error, false, initial),
            previous_window_input_attempted,
        )),
        Ok(Some((proxy, Some(index)))) => dispatch_action_with_focus(
            &proxy,
            index,
            request,
            &observation,
            session_id,
            previous_window_input_attempted,
        ),
        // As in the original route, failure to enumerate a unique fallback
        // action keeps the initial setup/position error.
        _ => Err(after_window_input(
            failure(preparation_error, false, initial),
            previous_window_input_attempted,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_input_phase_preserves_primary_failures_and_marks_pre_primary_input() {
        for primary_attempted in [false, true] {
            for window_input_attempted in [false, true] {
                let original = std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "primary actuator error",
                );
                let failure = after_window_input(
                    failure(
                        original.into(),
                        primary_attempted,
                        NativeElementTransport::Accessibility,
                    ),
                    window_input_attempted,
                );
                assert_eq!(
                    failure.dispatched,
                    primary_attempted || window_input_attempted
                );
                assert_eq!(
                    failure.transport,
                    if !primary_attempted && window_input_attempted {
                        NativeElementTransport::WindowSendEvent
                    } else {
                        NativeElementTransport::Accessibility
                    }
                );
                assert_eq!(failure.error.to_string(), "primary actuator error");
                assert_eq!(
                    failure
                        .error
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .kind(),
                    std::io::ErrorKind::ConnectionReset
                );
            }
        }
    }

    #[test]
    fn action_reader_display_preserves_the_public_cause_and_typed_error_chain() {
        let missing_action = ActionReadError(anyhow!("AT-SPI element does not implement Action"));
        assert_eq!(
            missing_action.to_string(),
            "AT-SPI element does not expose actions; refresh get_window_state(): AT-SPI element does not implement Action"
        );

        let cause = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reader disconnected");
        let error: anyhow::Error =
            ActionReadError(anyhow::Error::new(cause).context("reader failed")).into();
        assert_eq!(
            error.to_string(),
            "AT-SPI element does not expose actions; refresh get_window_state(): reader failed: reader disconnected"
        );
        let cause = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .expect("the original transport error must remain in the error chain");
        assert_eq!(cause.kind(), std::io::ErrorKind::ConnectionReset);
    }

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
