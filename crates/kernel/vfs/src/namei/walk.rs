extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::dentry::Dentry;
use crate::types::{FileType, KResult, VfsError};

use super::{components, follow_mount_down, may_lookup, LinkTarget, Nameidata, VfsPath, WalkOutcome, MAX_NESTED_LINKS, MAX_SYMLINK_DEPTH};

impl Nameidata {
    /// ONE component-walk pass. `validate` gates the D22 seqretry restarts (the final degraded pass passes `false` so the Arc result is taken as-is).
    /// Returns `Done(path)` or a `Restart` request. # C: O(components) + O(symlinks)
    pub(super) fn walk_inner(&mut self, path: &str, validate: bool) -> KResult<WalkOutcome> {
        // D22: snapshot the GLOBAL rename seqcount at the walk top (Linux
        // `read_seqbegin(&rename_lock)`). Any `d_move` anywhere advances it, so a
        // multi-component walk that raced a directory rename detects it via
        // `rename_lock_retry(m_seq)` and restarts — catching a sibling component
        // shifting under a rename that the per-dentry `d_seq` alone would miss.
        let m_seq = crate::dcache::rename_lock_read_begin();
        // Closure: a resolved `child` (snapshot `cseq`) was renamed under us iff
        // its per-dentry seqcount advanced OR the global rename seqcount did.
        // Only consulted when `validate` (the degraded final pass ignores it).
        let renamed = |child: &Arc<Dentry>, cseq: u32| -> bool {
            validate && (child.read_seqretry(cseq) || crate::dcache::rename_lock_retry(m_seq))
        };
        // D18 LOOKUP_EMPTY (Linux `AT_EMPTY_PATH`): an empty pathname is `ENOENT`
        // unless LOOKUP_EMPTY is set, in which case the walk operates on the
        // dirfd/cwd base — the empty component queue (below) breaks immediately
        // and returns the start `(mnt,dentry,inode)`. Centralizing the gate here
        // gives every path-taking `*at` syscall uniform empty-path semantics
        // instead of each handler re-implementing the AT_EMPTY_PATH check.
        if path.is_empty() && !self.flags.empty { return Err(VfsError::Enoent); }
        if path.as_bytes().first() == Some(&b'/') {
            // RESOLVE_BENEATH: an absolute pathname would jump to the (real)
            // root ABOVE the scoped dirfd → EXDEV (Linux `LOOKUP_BENEATH`).
            if self.flags.beneath_exdev { return Err(VfsError::Exdev); }
            self.to_root()?;
        }

        // LOOKUP_DIRECTORY from pathname syntax (`path::requires_dir`): a
        // trailing `/` (`foo/`), or a final `.` / `..` (`foo/.`, `foo/..`)
        // forces the final component to resolve to a directory (else ENOTDIR via
        // the check below), AND makes the final symlink be followed even under
        // `no_follow_final` (Linux `link_path_walk`: a trailing slash adds
        // LOOKUP_FOLLOW|LOOKUP_DIRECTORY to the last component). "/" itself
        // (len 1) is the root directory and resolves normally. The lexical
        // splitter drops the trailing `/` and `.`, so this requirement cannot be
        // recovered from `queue` alone — `requires_dir` reads the raw path.
        let trailing_slash = crate::path::requires_dir(path);
        if trailing_slash { self.flags.directory = true; }

        // LOOKUP_PARENT leaf type (Linux `nd->last_type`): a trailing `.`
        // (`dir/.`) is dropped by `components`, so the parent walk must resolve
        // `dir` FULLY and report `.` as the leaf — not stop before `dir`.
        // Detected from the raw path (the queue cannot carry the dropped `.`);
        // when set, the parent-stop is suppressed and `last_component` is fixed
        // to `.` after the loop. A trailing `..` survives in the queue and is
        // reported verbatim at the stop below (Linux `LAST_DOTDOT`).
        let trailing_dot = self.flags.parent && crate::path::last_segment(path) == ".";

        // Linux `nameidata` walk frames: an ACTIVE component list `(queue, idx)`
        // plus a stack of SUSPENDED frames (`nd->stack`). Following a symlink
        // SUSPENDS the active frame's remainder, makes the link target the new
        // active frame, and resumes the suspended remainder (Linux `put_link`)
        // once the target is fully consumed. This replaces the old
        // splice-and-restart (`queue.extend(remainder); idx = 0`), which
        // re-copied the trailing remainder and grew one queue per nested link
        // (O(n²) on deeply nested symlinks); each frame now owns only its own
        // components, and relative/absolute targets resolve from the right
        // directory context (`cur_*` for relative, `to_root()` for absolute)
        // exactly as before.
        let mut queue: Vec<String> = components(path);
        let mut idx = 0usize;
        let mut saved: Vec<(Vec<String>, usize)> = Vec::new();
        let mut last_component: Option<String> = None;

        loop {
            // Resume suspended link frames whose target is now consumed (Linux
            // `put_link` + walk continuation). Only a NON-empty remainder is ever
            // pushed, so a popped frame always has a component to process; an
            // empty stack with the active frame consumed ends the walk.
            while idx >= queue.len() {
                match saved.pop() {
                    // Linux `put_link`: the suspended remainder resumes, so the
                    // symlink whose target it followed is fully consumed — drop
                    // one level of nesting depth (`nd->depth--`). Stays in lock-
                    // step with `saved.len()` (the live link stack).
                    Some((q, i)) => { queue = q; idx = i; self.depth = self.depth.saturating_sub(1); }
                    None => break,
                }
            }
            if idx >= queue.len() { break; }

            // D23: BORROW the active component in place rather than cloning a
            // fresh `String` every iteration. The dcache probe (`d_lookup`),
            // the slow-path `i_op->lookup`/`d_add`, and the lexical checks all
            // take `&str`, so the walk needs no owned copy. The borrow ends
            // before the symlink branch's `core::mem::take(&mut queue)` (NLL:
            // `comp`'s last use precedes the queue mutation), so following a
            // link can still swap the active frame. Only the LOOKUP_PARENT leaf
            // (returned to the caller) is materialised to an owned `String`.
            let comp: &str = &queue[idx];
            idx += 1;
            // Final component of the WHOLE resolution: the active frame is
            // exhausted AND no suspended remainder follows (Linux: last component
            // with `nd->depth == 0`). A non-empty `saved` means more path follows
            // a symlink, so this component is not the trailing one.
            let is_final = idx >= queue.len() && saved.is_empty();

            // ENOTDIR: `comp` (a name OR `..`) is resolved WITHIN `cur_inode`,
            // so `cur_inode` must be a directory — including the PARENT of a
            // LOOKUP_PARENT leaf (Linux `link_path_walk` `!d_can_lookup` →
            // ENOTDIR). Checked BEFORE the `..` short-circuit so `foo/..` on a
            // non-dir `foo` is ENOTDIR rather than a silent walk-up (Linux
            // resolves `..` only from a directory). The walker enforces this
            // itself rather than trusting `i_op->lookup` to reject a non-dir, so
            // a non-directory prefix (`/a/file/b`) and a non-dir LOOKUP_PARENT
            // parent (`mknod("/a/file/leaf")`) both fail.
            if !matches!(self.cur_inode.file_type(), FileType::Directory) {
                return Err(VfsError::Enotdir);
            }

            // ENAMETOOLONG: a single component longer than NAME_MAX (255 bytes)
            // is rejected lexically as the walk consumes it (Linux
            // `link_path_walk` `hash_name` → `-ENAMETOOLONG`), even when the
            // whole pathname is well under PATH_MAX and even for a LOOKUP_PARENT
            // leaf (checked before the parent-stop below). `..` is a control
            // segment (≤2 bytes), never over-length, so it is exempt.
            if comp != ".." { crate::path::check_component(comp)?; }

            // LOOKUP_PARENT: stop BEFORE the final component, reporting it as
            // the leaf (Linux `path_parentat` / `nd->last`). `may_lookup`
            // (search permission, MAY_EXEC) runs FIRST — `link_path_walk` checks
            // it at the top of every component iteration, the final parent
            // included, so creating in a non-searchable dir is EACCES. The leaf
            // is reported VERBATIM: a trailing `..` surfaces as
            // `last_component == ".."` (Linux `LAST_DOTDOT`) instead of silently
            // walking up, a normal name as itself (`LAST_NORM`), letting the
            // caller reject `rmdir("..")` / `rename(.., "..")`. A trailing `.`
            // (`trailing_dot`, dropped by the splitter) is excluded here and
            // resolved fully, with `.` restored as the leaf after the loop.
            // LOOKUP_FOLLOW on a LOOKUP_PARENT walk (`open(O_CREAT)` without
            // O_EXCL/O_NOFOLLOW): the leaf itself may be a symlink, and the open
            // acts on what the link points at rather than on the link's own name.
            // The reference resolves that trailing component inside THIS walk —
            // `open_last_lookups` looks the leaf up and hands it to `step_into`
            // with WALK_TRAILING, which picks the link up and continues the walk
            // on its target — so the name finally created is the target's name in
            // the target's directory, and a dangling link is created THROUGH.
            // Only a LAST_NORM leaf takes this path: `..` (and the trailing `.`
            // handled by `trailing_dot`) are control segments the reference sends
            // to `handle_dots` instead, so they still stop here verbatim.
            let follow_leaf = is_final && self.flags.parent && !trailing_dot
                && self.flags.follow && comp != "..";
            if is_final && self.flags.parent && !trailing_dot && !follow_leaf {
                may_lookup(&self.cur_inode, &self.cred)?;
                last_component = Some(String::from(comp));
                break;
            }
            // The leaf name, materialised BEFORE the resolution below borrows and
            // then replaces the active frame. `Some` only for the followed-leaf
            // case, where the walk stops on a leaf that turns out not to be a
            // symlink (or not to exist) instead of stepping into it.
            let leaf_stop: Option<String> = if follow_leaf { Some(String::from(comp)) } else { None };

            // `.` and empty segments are already dropped by `components`
            // (single splitter in `path.rs`); only `..` and names reach here.
            if comp == ".." {
                let from_mnt = self.cur_mnt_id;
                let escaped = self.handle_dotdot();
                // RESOLVE_BENEATH: a `..` at the scoped root is an escape above
                // the dirfd → EXDEV (Linux), not a silent clamp.
                if self.flags.beneath_exdev && escaped { return Err(VfsError::Exdev); }
                // RESOLVE_NO_XDEV: a `..` that ascends OUT of the current mount
                // (back to the mountpoint in the parent mount) is rejected.
                if self.flags.no_xdev && self.cur_mnt_id != from_mnt { return Err(VfsError::Exdev); }
                continue;
            }

            // `may_lookup`: search permission (MAY_EXEC) on the current
            // directory before resolving a child within it (Linux).
            may_lookup(&self.cur_inode, &self.cred)?;

            // Resolve the named child (`child.rs`: dcache fast path, `i_op->lookup`
            // slow path, negative caching). One owner, so the trailing component
            // of a followed create is resolved by the same code as every other.
            let child = match self.lookup_child(comp)? {
                super::child::ChildLookup::Found(d) => d,
                super::child::ChildLookup::Restart => return Ok(WalkOutcome::Restart),
                // A leaf that is not there is the ORDINARY create case: the walk
                // stops with the parent it reached and the name the caller is
                // about to create (Linux `lookup_open` creates on a negative
                // dentry). Anywhere else a definitive miss is ENOENT.
                super::child::ChildLookup::Missing => match leaf_stop {
                    Some(name) => { last_component = Some(name); break; }
                    None => return Err(VfsError::Enoent),
                },
            };

            // D22: snapshot the resolved child's per-dentry rename seqcount
            // BEFORE reading its name/inode/crossing (Linux `read_seqcount_begin(
            // &child->d_seq)`). Re-checked (`renamed`) after the child is USED —
            // an advanced `d_seq` (or global `rename_lock`) means a `d_move`
            // rehomed it under us, so the result would be torn: restart the walk.
            let cseq = child.read_seqbegin();

            // Symlink handling — use the child's OWN inode (a mountpoint is a
            // directory, never a symlink, so this precedes mount crossing).
            if matches!(child.inode().map(|i| i.file_type()), Some(FileType::Symlink)) {
                // O_NOFOLLOW / AT_SYMLINK_NOFOLLOW: the FINAL symlink is returned
                // UNFOLLOWED (Linux `step_into` with LOOKUP_FOLLOW clear). The link
                // is NOT resolved, so RESOLVE_NO_SYMLINKS does not apply to it —
                // this short-circuit precedes the `no_symlinks` ELOOP gate so
                // `open(symlink, O_PATH|O_NOFOLLOW)` under RESOLVE_NO_SYMLINKS
                // yields the link itself, not ELOOP (Linux `pick_link`'s
                // NO_SYMLINKS gate fires only when a link is actually followed).
                // A trailing slash forces the final symlink to be followed even
                // under no_follow_final (Linux: `link/` follows `link`, then the
                // target must be a directory), so it does NOT short-circuit here.
                // D30 LOOKUP_FOLLOW: an explicit `follow` likewise OVERRIDES
                // no_follow_final (Linux's flag set never holds both; FOLLOW
                // wins), so the trailing link is resolved rather than returned.
                if is_final && self.flags.no_follow_final && !self.flags.follow && !trailing_slash {
                    // Final component complication: legitimize (rcu → ref) and
                    // validate the rename seqcounts before returning the link.
                    if !self.unlazy_walk(&child, cseq, m_seq) { return Ok(WalkOutcome::Restart); }
                    if renamed(&child, cseq) { return Ok(WalkOutcome::Restart); }
                    let inode = child.inode().ok_or(VfsError::Enoent)?;
                    return Ok(WalkOutcome::Done(VfsPath { mnt_id: self.cur_mnt_id, dentry: child, inode, last_component: None }));
                }
                // About to FOLLOW the link (a blocking `get_link` + jump): leave
                // LOOKUP_RCU first (Linux `try_to_unlazy` before `get_link`).
                if !self.unlazy_walk(&child, cseq, m_seq) { return Ok(WalkOutcome::Restart); }
                // About to FOLLOW the link → RESOLVE_NO_SYMLINKS forbids it
                // (Linux `pick_link`: `if (nd->flags & LOOKUP_NO_SYMLINKS) -ELOOP`).
                // Reaches here for every intermediate symlink, and for a final
                // symlink that IS being followed (no O_NOFOLLOW, or trailing `/`).
                if self.flags.no_symlinks { return Err(VfsError::Eloop); }
                // Linux `pick_link`: bump the TOTAL link count and ELOOP past
                // MAXSYMLINKS — the monotonic cycle guard (catches every loop,
                // however deeply or shallowly nested). The NESTING cap is
                // enforced separately at the frame push below.
                self.total_link_count += 1;
                if self.total_link_count > MAX_SYMLINK_DEPTH { return Err(VfsError::Eloop); }
                // `i_op->get_link` (Linux `get_link`): a MAGIC link
                // (`/proc/<pid>/fd/<n>` …) yields a resolved JUMP target the
                // walk RESETS to (Linux `nd_jump_link`); an ordinary symlink
                // yields its BODY string to splice as a new path frame. Only
                // magic inodes ever take the `Jump` arm, so the common symlink
                // walk below is byte-for-byte unchanged.
                // Linux `get_link` (fs/namei.c): a symlink traversed by the walk
                // has ITS atime bumped before the body is read, so `relatime`
                // sees a followed symlink as an access.
                let link_inode = child.inode().ok_or(VfsError::Enoent)?;
                crate::atime::touch_atime(self.cur_mnt_id, &link_inode);
                match link_inode.follow_link()? {
                    LinkTarget::Jump(vp) => {
                        // RESOLVE_NO_MAGICLINKS (Linux `nd_jump_link` under
                        // LOOKUP_NO_MAGICLINKS): a magic link followed in the
                        // walk → ELOOP. The open/dup layer enforces the same on
                        // its `/proc/self/fd/N` short-circuit.
                        if self.flags.no_magiclinks { return Err(VfsError::Eloop); }
                        // Linux `nd_jump_link`: reset the current
                        // `(mnt,dentry,inode)` to the jump target. The ACTIVE
                        // frame's REMAINING components (`queue`/`idx` already
                        // advanced past this link) resume from the new position —
                        // no frame push, no string splice, no nesting bump. The
                        // jump target is an already-resolved path (an open file's
                        // `(mnt,dentry)`), so no mount-crossing follow is needed.
                        self.cur_mnt_id = vp.mnt_id;
                        self.cur_dentry = vp.dentry;
                        self.cur_inode  = vp.inode;
                        // D22: a `d_move` of the magic-link dentry under us taints
                        // the jump read, so restart.
                        if renamed(&child, cseq) { return Ok(WalkOutcome::Restart); }
                        continue;
                    }
                    LinkTarget::Path(bytes) => {
                        let target = crate::path::path_from_bytes(&bytes);
                        // Suspend the active frame's remainder (Linux `nd->stack` push)
                        // and make the link target the new active frame; the remainder is
                        // resumed (Linux `put_link`) when the target is consumed. Skip the
                        // push when nothing remains, so an exhausted frame is never stacked
                        // — keeping the resume loop and `is_final` exact.
                        if idx < queue.len() {
                            saved.push((core::mem::take(&mut queue), idx));
                            // Linux `nd->depth++` — one more suspended link frame is
                            // live. Cap the NESTING separately from the total count: a
                            // pathologically deep stack of pending remainders is ELOOP
                            // at MAX_NESTED_LINKS even while the total is under
                            // MAXSYMLINKS (Linux rejects both over-nesting and
                            // over-counting). `saved.len() == self.depth` holds.
                            self.depth += 1;
                            if self.depth > MAX_NESTED_LINKS { return Err(VfsError::Eloop); }
                        }
                        queue = components(&target);
                        idx = 0;
                        if target.as_bytes().first() == Some(&b'/') {
                            // RESOLVE_BENEATH (`beneath_exdev`): an absolute symlink
                            // target escapes above the scoped dirfd → EXDEV (Linux),
                            // checked BEFORE the jump-to-root.
                            if self.flags.beneath_exdev { return Err(VfsError::Exdev); }
                            // Absolute target jumps to the resolution root (Linux
                            // `nd_jump_root`), exactly as an absolute pathname does
                            // (`to_root` at the top of `walk`). Under a CONFINED root —
                            // chroot (`beneath`, wired by `pathresolve::resolution_root`)
                            // or RESOLVE_IN_ROOT — `root` IS the jail/dirfd, so the
                            // target restarts there and cannot escape: a chroot'd
                            // `/etc/foo` symlink resolves to `<jail>/etc/foo`, NOT the
                            // global tree.
                            self.to_root()?;
                        }
                        // D22: the link's name/target was consumed — a `d_move` of the
                        // symlink dentry under us taints the target read, so restart.
                        if renamed(&child, cseq) { return Ok(WalkOutcome::Restart); }
                        // Relative target keeps walking from the symlink's directory.
                        continue;
                    }
                }
            }

            // Followed-leaf walk whose leaf is NOT a symlink: the caller asked for
            // a parent and a name, so the walk stops on the parent rather than
            // stepping into the leaf (the reference's `open_last_lookups` likewise
            // hands a non-link trailing dentry straight to `do_open` instead of
            // walking past it). The leaf exists — whether that is EEXIST, a plain
            // open, or EISDIR is the caller's decision, exactly as for a leaf the
            // parent-stop above reported.
            if let Some(name) = leaf_stop {
                last_component = Some(name);
                break;
            }

            let child_inode = child.inode().ok_or(VfsError::Enoent)?;

            // Automount triggers run before ordinary mount crossing. The hook
            // may graft a mount onto `child`, after which `follow_mount_down`
            // crosses it through the same generic mount path as explicit mounts.
            if !self.flags.no_automount && child_inode.i_op().is_automount(&child_inode) {
                if self.rcu && !self.unlazy_walk(&child, cseq, m_seq) { return Ok(WalkOutcome::Restart); }
                child_inode.i_op().automount(&child_inode, &child, self.cur_mnt_id)?;
            }

            // Mount crossing / final component are complications: legitimize
            // (leave LOOKUP_RCU) when crossing into a mount (reads the mount
            // tables) or at the trailing component (Linux `complete_walk`).
            if self.rcu && (is_final || child.is_mounted())
                && !self.unlazy_walk(&child, cseq, m_seq) { return Ok(WalkOutcome::Restart); }

            // KEYSTONE — mount crossing (Linux `__follow_mount`): switch the
            // current dentry to the mounted fs's `s_root`, looping for stacked
            // overmounts. `VfsPath.dentry` thus becomes the mounted-fs dentry.
            let (nd, ni, nm) = follow_mount_down(child.clone(), self.cur_mnt_id)?;
            // RESOLVE_NO_XDEV: a component that descends INTO a mount (the
            // crossed mount id differs) is rejected (Linux `LOOKUP_NO_XDEV`).
            if self.flags.no_xdev && nm != self.cur_mnt_id { return Err(VfsError::Exdev); }
            // D22: validate the child's binding survived our use (name read +
            // mount crossing) before committing it as the new walk position.
            if renamed(&child, cseq) { return Ok(WalkOutcome::Restart); }
            self.cur_dentry = nd;
            self.cur_inode = ni;
            self.cur_mnt_id = nm;
        }

        // LOOKUP_DIRECTORY: the resolved target must be a directory.
        if self.flags.directory && !matches!(self.cur_inode.file_type(), FileType::Directory) {
            return Err(VfsError::Enotdir);
        }

        // Trailing `.` under LOOKUP_PARENT: the parent is the fully-resolved
        // directory and the leaf is `.` (Linux `LAST_DOT`) — `components`
        // dropped the `.`, so it is restored here so the caller can reject
        // `rmdir(".")` / `unlink(".")` without re-parsing the path.
        if trailing_dot { last_component = Some(String::from(".")); }

        // D22: a final whole-path consistency gate (Linux `read_seqretry(
        // &rename_lock)` at walk end) — a directory rename anywhere along the
        // resolved path during the walk taints the result; restart.
        if validate && crate::dcache::rename_lock_retry(m_seq) { return Ok(WalkOutcome::Restart); }

        Ok(WalkOutcome::Done(VfsPath {
            mnt_id: self.cur_mnt_id,
            dentry: self.cur_dentry.clone(),
            inode: self.cur_inode.clone(),
            last_component,
        }))
    }
}
