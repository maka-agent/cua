// SPDX-License-Identifier: MIT

//! Shared pre-order bookkeeping for observation and early-exit native lookup.

use super::RawObjectRef;

pub(super) type Entry = (RawObjectRef, usize, bool, usize);

/// The same ordered stack serves both consumers. Only native lookup retains
/// ancestry, so ordinary snapshots do not copy paths they never use.
pub(super) struct Traversal {
    pending: Vec<Entry>,
    path: Option<Vec<RawObjectRef>>,
}

impl Traversal {
    pub(super) fn observation(pending: Vec<Entry>) -> Self {
        Self {
            pending,
            path: None,
        }
    }

    pub(super) fn lookup(root: RawObjectRef, frame: usize) -> Self {
        Self {
            pending: vec![(root, 0, false, frame)],
            path: Some(Vec::new()),
        }
    }

    pub(super) fn pop(&mut self) -> Option<Entry> {
        let entry = self.pending.pop()?;
        if let Some(path) = &mut self.path {
            path.truncate(entry.1);
            path.push(entry.0.clone());
        }
        Some(entry)
    }

    pub(super) fn push(&mut self, entry: Entry) {
        self.pending.push(entry);
    }

    pub(super) fn len(&self) -> usize {
        self.pending.len()
    }

    /// Current root-to-node path, materialized only for an actual match.
    pub(super) fn path(&self) -> &[RawObjectRef] {
        self.path.as_deref().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(path: &str) -> RawObjectRef {
        RawObjectRef {
            name: ":1.7".into(),
            path: path.into(),
        }
    }

    #[test]
    fn lookup_keeps_only_the_current_preorder_ancestry() {
        let mut walk = Traversal::lookup(object("/root"), 2);
        let (_, depth, _, frame) = walk.pop().unwrap();
        assert_eq!((depth, frame), (0, 2));
        walk.push((object("/second"), 1, false, frame));
        walk.push((object("/first"), 1, false, frame));
        walk.pop().unwrap();
        walk.push((object("/leaf"), 2, false, frame));
        walk.pop().unwrap();
        assert_eq!(
            walk.path()
                .iter()
                .map(|node| node.path.as_str())
                .collect::<Vec<_>>(),
            ["/root", "/first", "/leaf"]
        );
        walk.pop().unwrap();
        assert_eq!(
            walk.path()
                .iter()
                .map(|node| node.path.as_str())
                .collect::<Vec<_>>(),
            ["/root", "/second"]
        );
        assert_eq!(walk.len(), 0);
    }

    #[test]
    fn observation_order_does_not_retain_lookup_paths() {
        let mut walk = Traversal::observation(vec![(object("/root"), 0, false, 0)]);
        assert_eq!(walk.pop().unwrap().0.path, "/root");
        assert!(walk.path().is_empty());
    }
}
