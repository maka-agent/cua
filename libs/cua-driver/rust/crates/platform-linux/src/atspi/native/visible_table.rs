// SPDX-License-Identifier: MIT

//! Visible-cell sampling shared by native observation and element lookup.

use super::{accessible_for, call, raw_child_count, raw_children, RawObjectRef};
use anyhow::{anyhow, bail, Result};
use atspi::proxy::component::ComponentProxy;
use atspi::{CoordType, State};
use atspi_connection::AccessibilityConnection;
use std::collections::HashSet;
use std::fmt::Display;
use std::future::Future;

const SAMPLE_LIMIT: usize = 5000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rect {
    pub(super) left: i64,
    pub(super) top: i64,
    pub(super) right: i64,
    pub(super) bottom: i64,
}

pub(super) struct Children {
    pub(super) objects: Vec<RawObjectRef>,
    pub(super) sampled: bool,
}

async fn request<T, E: Display>(
    session_id: Option<&str>,
    operation: &str,
    future: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    super::element::check(session_id)?;
    let reply = call(future).await;
    super::element::check(session_id)?;
    reply
        .ok_or_else(|| anyhow!("{operation} did not answer in time"))?
        .map_err(|error| anyhow!("{operation}: {error}"))
}

async fn component<'a>(
    conn: &'a AccessibilityConnection,
    object: &RawObjectRef,
    session_id: Option<&str>,
) -> Result<ComponentProxy<'a>> {
    request(
        session_id,
        "Component proxy",
        ComponentProxy::builder(conn.connection())
            .cache_properties(atspi::zbus::proxy::CacheProperties::No)
            .destination(object.name.clone())?
            .path(object.path.clone())?
            .build(),
    )
    .await
}

pub(super) async fn bounds(
    conn: &AccessibilityConnection,
    object: &RawObjectRef,
    session_id: Option<&str>,
) -> Result<Rect> {
    let proxy = component(conn, object, session_id).await?;
    let (x, y, width, height) = request(
        session_id,
        "Component.GetExtents",
        proxy.get_extents(CoordType::Screen),
    )
    .await?;
    Ok(Rect {
        left: i64::from(x),
        top: i64::from(y),
        right: i64::from(x) + i64::from(width),
        bottom: i64::from(y) + i64::from(height),
    })
}

pub(super) async fn children(
    conn: &AccessibilityConnection,
    object: &RawObjectRef,
    remaining: usize,
    session_id: Option<&str>,
) -> Result<Children> {
    let accessible = request(session_id, "Accessible proxy", accessible_for(conn, object)).await?;
    let role = request(
        session_id,
        "Accessible.GetRoleName",
        accessible.get_role_name(),
    )
    .await?;
    children_with_role(conn, object, &role, remaining, session_id).await
}

pub(super) async fn children_with_role(
    conn: &AccessibilityConnection,
    object: &RawObjectRef,
    role: &str,
    remaining: usize,
    session_id: Option<&str>,
) -> Result<Children> {
    if role == "table" {
        let count = request(
            session_id,
            "Accessible.ChildCount",
            raw_child_count(conn.connection(), object),
        )
        .await;
        if matches!(count, Ok(count) if count >= 5001) {
            if let Ok(objects) = visible_cells(conn, object, remaining, session_id).await {
                return Ok(Children {
                    objects,
                    sampled: true,
                });
            }
        }
        super::element::check(session_id)?;
    }
    let objects = request(
        session_id,
        "Accessible.GetChildren",
        raw_children(conn.connection(), object),
    )
    .await?;
    Ok(Children {
        objects,
        sampled: false,
    })
}

pub(super) async fn visible_cells(
    conn: &AccessibilityConnection,
    table: &RawObjectRef,
    remaining: usize,
    session_id: Option<&str>,
) -> Result<Vec<RawObjectRef>> {
    super::element::check(session_id)?;
    if remaining == 0 {
        return Ok(Vec::new());
    }
    let accessible = request(session_id, "Accessible proxy", accessible_for(conn, table)).await?;
    let interfaces: Vec<String> = request(
        session_id,
        "Accessible.GetInterfaces",
        accessible.inner().call("GetInterfaces", &()),
    )
    .await?;
    if !interfaces.iter().any(|name| name == "org.a11y.atspi.Table") {
        bail!("visible-cell sampling requires the Table interface");
    }
    let states = request(session_id, "Accessible.GetState", accessible.get_state()).await?;
    if !states.contains(State::Visible) || !states.contains(State::Showing) {
        bail!("visible-cell sampling requires a visible, showing table");
    }
    let area = bounds(conn, table, session_id).await?;
    if area.left >= area.right || area.top >= area.bottom {
        bail!("visible-cell sampling requires positive table bounds");
    }
    let component = component(conn, table, session_id).await?;
    let mut cells = Vec::new();
    let mut seen = HashSet::new();
    let mut samples = 0;
    let mut y = area.top;
    while y < area.bottom && cells.len() < remaining && samples < SAMPLE_LIMIT {
        let screen_y = i32::try_from(y)?;
        let mut x = area.left;
        let mut next_y = area.bottom;
        while x < area.right && cells.len() < remaining && samples < SAMPLE_LIMIT {
            let screen_x = i32::try_from(x)?;
            let (name, path): (String, atspi::zbus::zvariant::OwnedObjectPath) = request(
                session_id,
                "Component.GetAccessibleAtPoint",
                component.inner().call(
                    "GetAccessibleAtPoint",
                    &(screen_x, screen_y, CoordType::Screen),
                ),
            )
            .await?;
            if path.as_str() == "/org/a11y/atspi/null" {
                bail!("table sampling returned no accessible at the screen point");
            }
            let cell = RawObjectRef {
                name: if name.is_empty() {
                    table.name.clone()
                } else {
                    name
                },
                path: path.to_string(),
            };
            if cell.name == table.name && cell.path == table.path {
                bail!("table sampling returned the table itself");
            }
            let accessible =
                request(session_id, "Accessible proxy", accessible_for(conn, &cell)).await?;
            let role = request(
                session_id,
                "Accessible.GetRoleName",
                accessible.get_role_name(),
            )
            .await?;
            if role != "table cell" {
                bail!("table sampling returned a non-cell accessible");
            }
            let states = request(session_id, "Accessible.GetState", accessible.get_state()).await?;
            samples += 1;
            if !states.contains(State::Visible) || !states.contains(State::Showing) {
                bail!("table sampling returned a cell that is not visible and showing");
            }
            let frame = bounds(conn, &cell, session_id).await?;
            if frame.bottom <= y {
                next_y = y + 1;
                break;
            }
            if frame.right <= x {
                next_y = next_y.min(frame.bottom);
                x += 1;
                continue;
            }
            if frame.left >= area.right
                || frame.top >= area.bottom
                || frame.right <= area.left
                || frame.bottom <= area.top
            {
                bail!("table sampling returned a cell outside the table bounds");
            }
            x = frame.right.min(area.right);
            next_y = next_y.min(frame.bottom);
            if seen.insert((cell.name.clone(), cell.path.clone())) {
                cells.push(cell);
            }
        }
        y = next_y;
    }
    Ok(cells)
}
