// Path lookup and the edits a handover makes: properties set, properties
// deleted, reservations added and removed.
//
// Every edit reports whether it CHANGED anything, because the reference
// distinguishes "removed" from "was not there" — a delete of an absent
// property is success, a delete that fails for any other reason is not.

extern crate alloc;
use alloc::vec::Vec;

use super::{Fdt, Node, Prop};

impl Node {
    /// The child named `name`, or `None`.
    /// # C: O(N_children)
    pub fn child(&self, name: &[u8]) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// The child named `name`, creating it when absent.
    /// # C: O(N_children)
    pub fn child_or_add(&mut self, name: &[u8]) -> &mut Node {
        match self.children.iter().position(|c| c.name == name) {
            Some(i) => &mut self.children[i],
            None => { self.children.push(Node::new(name)); self.children.last_mut().unwrap() }
        }
    }

    /// A property's value.
    /// # C: O(N_props)
    pub fn prop(&self, name: &[u8]) -> Option<&[u8]> {
        self.props.iter().find(|p| p.name == name).map(|p| p.val.as_slice())
    }

    /// Set a property, replacing any value already there.
    ///
    /// Replacement keeps the property's ORIGINAL position among its siblings.
    /// Nothing in the format depends on property order, but a handover that
    /// reordered the tree would make every diff against the source tree
    /// unreadable, and the diff is how a wrong edit is found.
    /// # C: O(N_props + len)
    pub fn set_prop(&mut self, name: &[u8], val: &[u8]) {
        match self.props.iter_mut().find(|p| p.name == name) {
            Some(p) => p.val = val.to_vec(),
            None => self.props.push(Prop { name: name.to_vec(), val: val.to_vec() }),
        }
    }

    /// Set a property whose value is one big-endian u64 — the width the
    /// device-tree bindings give `linux,initrd-start` and its siblings.
    /// # C: O(N_props)
    pub fn set_prop_u64(&mut self, name: &[u8], v: u64) {
        self.set_prop(name, &v.to_be_bytes());
    }

    /// Set a property whose value is a NUL-terminated string.
    ///
    /// The NUL is part of the value: a `bootargs` without one is a string the
    /// next reader runs off the end of.
    /// # C: O(N_props + len)
    pub fn set_prop_string(&mut self, name: &[u8], s: &[u8]) {
        let mut v = s.to_vec();
        v.push(0);
        self.set_prop(name, &v);
    }

    /// Set a property with no value — the empty marker form.
    /// # C: O(N_props)
    pub fn set_prop_empty(&mut self, name: &[u8]) { self.set_prop(name, &[]); }

    /// Remove a property; `true` when one was there.
    /// # C: O(N_props)
    pub fn del_prop(&mut self, name: &[u8]) -> bool {
        match self.props.iter().position(|p| p.name == name) {
            Some(i) => { self.props.remove(i); true }
            None => false,
        }
    }
}

impl Fdt {
    /// The node at an absolute path such as `/chosen`, or `None`.
    /// # C: O(path depth * N_children)
    pub fn node(&self, path: &[u8]) -> Option<&Node> {
        let mut n = &self.root;
        for part in split_path(path) { n = n.child(part)?; }
        Some(n)
    }

    /// The node at an absolute path, creating any component that is missing.
    ///
    /// `/chosen` frequently does not exist on a tree that booted with no
    /// command line, and the handover has to write into it regardless.
    /// # C: O(path depth * N_children)
    pub fn node_or_add(&mut self, path: &[u8]) -> &mut Node {
        let mut n = &mut self.root;
        for part in split_path(path) { n = n.child_or_add(part); }
        n
    }

    /// Add a memory reservation.
    /// # C: O(1)
    pub fn add_mem_rsv(&mut self, addr: u64, size: u64) { self.rsv.push((addr, size)); }

    /// Remove the reservation exactly matching `(addr, size)`; `true` when one
    /// was there.
    ///
    /// Exact match, because a reservation that merely overlaps belongs to
    /// something else: dropping it would hand the new kernel memory another
    /// owner still holds.
    /// # C: O(N_rsv)
    pub fn del_mem_rsv(&mut self, addr: u64, size: u64) -> bool {
        match self.rsv.iter().position(|&(a, s)| a == addr && s == size) {
            Some(i) => { self.rsv.remove(i); true }
            None => false,
        }
    }
}

/// Split an absolute path into its components, dropping empties so `/`,
/// `//chosen` and `/chosen/` all name what they look like.
fn split_path(path: &[u8]) -> Vec<&[u8]> {
    path.split(|&c| c == b'/').filter(|p| !p.is_empty()).collect()
}
