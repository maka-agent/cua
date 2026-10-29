// SPDX-License-Identifier: MIT
//! Native candidate policy over the existing X11 inventory primitives.
//! Seed union/order, DFS, 10,000 seen-ID limit and exact focus equality are
//! proven by ELF6d CLI ev_ce687; the three seed/focus literals by Root's
//! mapped fixed-byte reads. Attrs bool and type projection are independently
//! closed below; descriptor edge cases and live behavior remain unverified.

use super::*;
use serde_json::{Value, json};
use std::collections::HashSet;

fn words(conn:&RustConnection,xid:Window,name:&[u8])->Result<Vec<u32>> {
    let atom=conn.intern_atom(true,name)?.reply()?.atom;
    if atom==0 {return Ok(Vec::new());}
    let reply=conn.get_property(false,xid,atom,AtomEnum::ANY,0,u32::MAX)?.reply()?;
    Ok(reply.value32().map(Iterator::collect).unwrap_or_default())
}

fn nonempty(conn:&RustConnection,xid:Window,name:&[u8])->bool {
    let Ok(cookie)=conn.intern_atom(true,name) else {return false;};
    let Ok(atom)=cookie.reply() else {return false;};
    if atom.atom==0 {return false;}
    conn.get_property(false,xid,atom.atom,AtomEnum::ANY,0,u32::MAX).ok()
        .and_then(|cookie|cookie.reply().ok()).is_some_and(|reply|!reply.value.is_empty())
}

fn chosen_focus(conn:&RustConnection,root:Window)->Option<Window> {
    // A first value zero remains Some(0); only empty/failure takes fallback.
    words(conn,root,b"_NET_ACTIVE_WINDOW").ok().and_then(|values|values.first().copied())
        .or_else(||conn.get_input_focus().ok()?.reply().ok().map(|reply|reply.focus))
}

fn ordered_candidates(conn:&RustConnection,root:Window)->Result<Vec<Window>> {
    let mut seen=HashSet::new();let mut output=Vec::new();
    for name in [b"_NET_CLIENT_LIST_STACKING".as_slice(),b"_NET_CLIENT_LIST".as_slice()] {
        for xid in words(conn,root,name).unwrap_or_default() {if seen.insert(xid) {output.push(xid);}}
    }
    let mut pending=conn.query_tree(root)?.reply()?.children.into_iter().map(|xid|(xid,true)).collect::<Vec<_>>();
    while seen.len()<10_000 {
        let Some((xid,root_child))=pending.pop() else {break;};
        let attributes=match conn.get_window_attributes(xid).ok().and_then(|cookie|cookie.reply().ok()) {
            Some(attributes) if attributes.map_state==MapState::VIEWABLE=>attributes,
            _=>continue,
        };
        // Exact names are independently byte-verified in Root's second
        // mapped fixed-byte receipt; control-flow order is from ev_ce687.
        let mut client=false;
        for name in [b"_NET_WM_WINDOW_TYPE".as_slice(),b"WM_STATE".as_slice(),b"WM_TRANSIENT_FOR".as_slice(),b"WM_CLASS".as_slice()] {
            if nonempty(conn,xid,name) {client=true;break;}
        }
        if !client&&root_child {
            client=[b"_NET_WM_NAME".as_slice(),b"WM_NAME".as_slice()].into_iter().any(|name|nonempty(conn,xid,name));
            // Original225c1d wire+27 ->r8b;225ce1 sret+0x33 ->caller
            // rsp+0x3b. The protocol names wire27 override_redirect.
            client|=attributes.override_redirect;
        }
        if client&&seen.insert(xid) {output.push(xid);}
        // Accepted and duplicate clients are still descended into. No added
        // depth cap; the actual X server tree is acyclic.
        if let Some(children)=conn.query_tree(xid).ok().and_then(|cookie|cookie.reply().ok()).map(|reply|reply.children) {
            pending.extend(children.into_iter().map(|xid|(xid,false)));
        }
    }
    Ok(output)
}

fn normalize_window_type(name:&[u8])->String {
    // CLI closures 87390 and 877d0: lossy UTF-8, exact prefix removal
    // when present, then ASCII-only case conversion. Unknown prefixes remain.
    let name=String::from_utf8_lossy(name);
    name.strip_prefix("_NET_WM_WINDOW_TYPE_").unwrap_or(&name).to_ascii_lowercase()
}

pub fn list() -> Result<Vec<Value>> {
    let (conn, screen) = RustConnection::connect(None)?;
    let root = conn.setup().roots[screen].root;
    let focused=chosen_focus(&conn,root);
    let windows=ordered_candidates(&conn,root)?;
    let modal_atom = conn.intern_atom(true, b"_NET_WM_STATE_MODAL")?.reply()?.atom;
    let owners = OwnerResolver::new(&conn);
    let mut output = Vec::new();
    for xid in windows {
        let Ok(attributes) = conn.get_window_attributes(xid)?.reply() else { continue; };
        if attributes.map_state != MapState::VIEWABLE { continue; }
        let Ok(geometry) = conn.get_geometry(xid)?.reply() else { continue; };
        let Ok(origin) = conn.translate_coordinates(xid, root, 0, 0)?.reply() else { continue; };
        let app = get_window_class(&conn, xid)
            .map(|(instance, class)| if class.is_empty() { instance } else { class })
            .unwrap_or_default();
        let states=words(&conn,xid,b"_NET_WM_STATE").unwrap_or_default();
        let mut record = json!({
            "id":xid, "pid":owners.owner_pid(xid), "app":app,
            "x":origin.dst_x,"y":origin.dst_y,
            "width":geometry.width,"height":geometry.height,
            "focused":focused == Some(xid),
            "modal":modal_atom != 0 && states.contains(&modal_atom),
        });
        if let Ok(title) = get_window_title(&conn, xid) { if !title.is_empty() {record["title"] = title.into();} }
        if let Some(atom) = words(&conn,xid,b"_NET_WM_WINDOW_TYPE").unwrap_or_default().first() {
            // Closure87460 turns a failed GetAtomName into None; it does not
            // abort the whole list or drop an otherwise valid window record.
            if let Some(name)=conn.get_atom_name(*atom).ok().and_then(|cookie|cookie.reply().ok()).map(|reply|reply.name) {
                record["window_type"]=normalize_window_type(&name).into();
            }
        }
        output.push(record);
    }
    Ok(output)
}

#[cfg(test)]
mod native_window_type_tests {
    use super::*;
    #[test]
    fn native_type_projection_preserves_unknown_names_and_only_lowercases_ascii() {
        assert_eq!(normalize_window_type(b"_NET_WM_WINDOW_TYPE_DIALOG"),"dialog");
        assert_eq!(normalize_window_type(b"CUSTOM_TYPE"),"custom_type");
        assert_eq!(normalize_window_type(b"_NET_WM_WINDOW_TYPE_"),"");
        assert_eq!(normalize_window_type(b"_net_wm_window_type_DIALOG"),"_net_wm_window_type_dialog");
        assert_eq!(normalize_window_type("ÄBC".as_bytes()),"Äbc");
        assert_eq!(normalize_window_type(b"\xffA"),"\u{fffd}a");
    }
}
