// Per-cgroup BPF attach-list algebra — `struct cgroup_bpf` in
// `include/linux/bpf-cgroup-defs.h` and the list operations in
// kernel/bpf/cgroup.c:
//
//   `hierarchy_allows_attach()`   ancestor veto on a new attach
//   `find_attach_entry()`         single-attach replace / MULTI duplicate
//   `get_prog_list()`             BEFORE/AFTER anchor resolution
//   `insert_pl_to_hlist()`        list position for a fresh entry
//   `find_detach_entry()`         which entry a detach removes
//   `compute_effective_progs()`   self+ancestor program array
//
// No target gate: the errno ladder is hosted-tested in `cgattach/tests.rs`,
// per `docs/53` and the phantom-test rule in CLAUDE.md. The kernel-side
// store that binds these to real cgroup ids lives in `cgstore.rs`.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::uapi;
use super::uapi::attach_flags as af;

/// `struct bpf_prog_list` — one directly attached program plus the
/// per-entry flags that decide its position (`BPF_F_PREORDER`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry<P> { pub prog: P, pub id: u32, pub flags: u32 }

/// `cgrp->bpf.{progs,flags,revisions}[atype]` for one attach type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachList<P> { pub flags: u32, pub revision: u64, pub progs: Vec<Entry<P>> }

impl<P> AttachList<P> {
    /// # C: O(1)
    pub const fn new() -> Self { AttachList { flags: 0, revision: 0, progs: Vec::new() } }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.progs.is_empty() }
    /// # C: O(1)
    pub fn allows_multi(&self) -> bool { self.flags & af::ALLOW_MULTI != 0 }
    /// # C: O(len)
    fn preorder_count(&self) -> usize {
        self.progs.iter().filter(|e| e.flags & af::PREORDER != 0).count()
    }
}

impl<P> Default for AttachList<P> {
    fn default() -> Self { Self::new() }
}

/// Anchor a `BPF_F_BEFORE`/`BPF_F_AFTER` insertion refers to, already
/// resolved by the caller the way `bpf_get_anchor_prog()` /
/// `bpf_get_anchor_link()` do. `Link` can never match a cgroup prog list
/// entry attached by `BPF_PROG_ATTACH`, which is why Linux rejects it
/// there before any lookup runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Anchor<P> {
    None,
    Prog(P),
    Id(u32),
    /// The caller could not resolve the anchor (`bpf_prog_get()` on a bad
    /// `relative_fd`). Carried rather than raised so the errno surfaces
    /// exactly where `get_prog_list()` resolves it — after the shape
    /// checks, and after the hierarchy vetoes in `__cgroup_bpf_attach()`.
    Unresolved(Errno),
}

/// One `BPF_PROG_ATTACH` request against a single cgroup.
pub struct AttachReq<P> {
    pub prog: P,
    pub id: u32,
    pub replace: Option<P>,
    pub flags: u32,
    /// `attr->relative_fd`/`relative_id` — non-zero selects anchored
    /// insertion even without `BPF_F_ID`/`BPF_F_LINK`.
    pub id_or_fd: u32,
    /// `attr->expected_revision`; 0 means "don't care".
    pub revision: u64,
}

/// `hierarchy_allows_attach()` — walk the ancestors (nearest first). An
/// ancestor that allows MULTI ends the walk permissively; the first
/// ancestor holding exactly one program decides by its OVERRIDE bit.
/// # C: O(depth)
pub fn hierarchy_allows_attach<P>(ancestors: &[&AttachList<P>]) -> bool {
    for p in ancestors {
        if p.flags & af::ALLOW_MULTI != 0 { return true; }
        if p.progs.len() == 1 { return p.flags & af::ALLOW_OVERRIDE != 0; }
    }
    true
}

/// `__cgroup_bpf_attach()` for one cgroup, with `ancestors` ordered
/// parent-first. Flag-combination EINVALs precede the ESTALE revision
/// check, which precedes the two EPERM hierarchy vetoes, which precede
/// the `BPF_CGROUP_MAX_PROGS` E2BIG.
/// # C: O(len)
pub fn attach<P: Clone + PartialEq>(
    list: &mut AttachList<P>, ancestors: &[&AttachList<P>],
    req: AttachReq<P>, anchor: Anchor<P>,
) -> Result<(), Errno> {
    let f = req.flags;
    let saved = f & af::SAVED;
    if f & af::ALLOW_OVERRIDE != 0 && f & af::ALLOW_MULTI != 0 { return Err(Errno::Einval); }
    if f & af::REPLACE != 0 && f & af::ALLOW_MULTI == 0 { return Err(Errno::Einval); }
    if f & af::REPLACE != 0 && f & (af::BEFORE | af::AFTER) != 0 { return Err(Errno::Einval); }
    if req.replace.is_some() != (f & af::REPLACE != 0) { return Err(Errno::Einval); }
    if req.revision != 0 && req.revision != list.revision { return Err(Errno::Estale); }
    if !hierarchy_allows_attach(ancestors) { return Err(Errno::Eperm); }
    // "Disallow attaching non-overridable on top of existing overridable
    // in this cgroup. Disallow attaching multi-prog if overridable or none."
    if !list.progs.is_empty() && list.flags != saved { return Err(Errno::Eperm); }
    if list.progs.len() >= uapi::CGROUP_MAX_PROGS { return Err(Errno::E2big); }

    match find_attach_entry(list, &req, f & af::ALLOW_MULTI != 0)? {
        Some(i) => { list.progs[i] = Entry { prog: req.prog, id: req.id, flags: f }; }
        None => {
            let at = insert_index(list, f, req.id_or_fd, &anchor)?;
            list.progs.insert(at, Entry { prog: req.prog, id: req.id, flags: f });
        }
    }
    list.flags = saved;
    list.revision += 1;
    Ok(())
}

/// `find_attach_entry()`. `Ok(Some(i))` names an entry to overwrite in
/// place; `Ok(None)` means "insert a new one".
/// # C: O(len)
fn find_attach_entry<P: PartialEq>(
    list: &AttachList<P>, req: &AttachReq<P>, allow_multi: bool,
) -> Result<Option<usize>, Errno> {
    if !allow_multi {
        if list.progs.is_empty() { return Ok(None); }
        return Ok(Some(0));
    }
    let self_replaces = req.replace.as_ref() == Some(&req.prog);
    for e in &list.progs {
        // "disallow attaching the same prog twice"
        if e.prog == req.prog && !self_replaces { return Err(Errno::Einval); }
    }
    if let Some(r) = &req.replace {
        return list.progs.iter().position(|e| &e.prog == r).map(Some).ok_or(Errno::Enoent);
    }
    Ok(None)
}

/// `get_prog_list()` + `insert_pl_to_hlist()` collapsed to the index a
/// fresh entry takes. An unanchored attach appends (or prepends under
/// `BPF_F_BEFORE`); an anchored one lands adjacent to the anchor and
/// must agree with it on `BPF_F_PREORDER`.
/// # C: O(len)
fn insert_index<P: PartialEq>(
    list: &AttachList<P>, flags: u32, id_or_fd: u32, anchor: &Anchor<P>,
) -> Result<usize, Errno> {
    let is_before = flags & af::BEFORE != 0;
    let is_after = flags & af::AFTER != 0;
    let is_id = flags & af::ID != 0;
    let is_link = flags & af::LINK != 0;
    if is_link || is_id || id_or_fd != 0 {
        if is_before == is_after { return Err(Errno::Einval); }
        // `is_link && !link`: a BPF_PROG_ATTACH carries a program, never a
        // link, so an anchor named by link is rejected before any lookup.
        if is_link { return Err(Errno::Einval); }
    } else if !list.progs.is_empty() {
        if is_before && is_after { return Err(Errno::Einval); }
    }
    let found = match anchor {
        Anchor::None => None,
        Anchor::Unresolved(e) => return Err(*e),
        Anchor::Prog(p) => Some(list.progs.iter().position(|e| &e.prog == p).ok_or(Errno::Enoent)?),
        Anchor::Id(id) => Some(list.progs.iter().position(|e| e.id == *id).ok_or(Errno::Enoent)?),
    };
    let Some(i) = found else {
        // No anchor: BPF_F_PREORDER does not matter, since prepending or
        // appending to a combined list yields the same effective order.
        if list.progs.is_empty() { return Ok(0); }
        return Ok(if is_before { 0 } else { list.progs.len() });
    };
    let preorder = flags & af::PREORDER != 0;
    if (list.progs[i].flags & af::PREORDER != 0) != preorder { return Err(Errno::Einval); }
    Ok(if is_before { i } else { i + 1 })
}

/// `__cgroup_bpf_detach()`. `prog` is `None` when the caller could not
/// resolve `attach_bpf_fd`, which legacy single-attach cgroups accept.
/// # C: O(len)
pub fn detach<P: PartialEq>(
    list: &mut AttachList<P>, prog: Option<&P>, revision: u64,
) -> Result<(), Errno> {
    if revision != 0 && revision != list.revision { return Err(Errno::Estale); }
    let allow_multi = list.flags & af::ALLOW_MULTI != 0;
    let i = find_detach_entry(list, prog, allow_multi)?;
    list.progs.remove(i);
    list.revision += 1;
    if list.progs.is_empty() { list.flags = 0; }
    Ok(())
}

/// `find_detach_entry()`. # C: O(len)
fn find_detach_entry<P: PartialEq>(
    list: &AttachList<P>, prog: Option<&P>, allow_multi: bool,
) -> Result<usize, Errno> {
    if !allow_multi {
        // NONE and OVERRIDE cgroups allow detaching with an invalid fd.
        if list.progs.is_empty() { return Err(Errno::Enoent); }
        return Ok(0);
    }
    // Detaching one of several requires naming it.
    let p = prog.ok_or(Errno::Einval)?;
    list.progs.iter().position(|e| &e.prog == p).ok_or(Errno::Enoent)
}

/// `compute_effective_progs()` — the array a run walks, with `levels[0]`
/// the cgroup itself followed by each ancestor up to the root. A level
/// contributes only when nothing has been collected yet or it allows
/// MULTI. `BPF_F_PREORDER` entries occupy the front of the array in
/// root-to-leaf order; the rest follow leaf-to-root.
/// # C: O(depth · len)
pub fn effective<P: Clone>(levels: &[&AttachList<P>]) -> Vec<P> {
    let mut cnt = 0usize;
    let mut pre = 0usize;
    for l in levels {
        if cnt == 0 || l.allows_multi() { cnt += l.progs.len(); pre += l.preorder_count(); }
    }
    let mut out: Vec<Option<P>> = alloc::vec![None; cnt];
    let mut fstart = pre;
    let mut bstart = pre as isize - 1;
    let mut n = 0usize;
    for l in levels {
        if n > 0 && !l.allows_multi() { continue; }
        let init_bstart = bstart;
        for e in &l.progs {
            if e.flags & af::PREORDER != 0 {
                out[bstart as usize] = Some(e.prog.clone());
                bstart -= 1;
            } else {
                out[fstart] = Some(e.prog.clone());
                fstart += 1;
            }
            n += 1;
        }
        let (mut i, mut j) = (bstart + 1, init_bstart);
        while i < j { out.swap(i as usize, j as usize); i += 1; j -= 1; }
    }
    out.into_iter().flatten().collect()
}

#[cfg(test)]
#[path = "cgattach/tests.rs"]
mod tests;
