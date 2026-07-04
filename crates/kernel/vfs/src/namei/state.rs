extern crate alloc;
use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{KResult, VfsError};

use super::{dotdot_step, follow_mount_down, Cred, LookupFlags, VfsPath};

pub struct Nameidata {
    pub cur_mnt_id: u64,
    pub cur_dentry: Arc<Dentry>,
    pub cur_inode: InodeRef,
    pub root_mnt_id: u64,
    pub root_dentry: Arc<Dentry>,
    /// Linux `nd->depth` — symlink NESTING depth: the count of suspended
    /// link-remainder frames currently on the resume stack (rises on a frame
    /// push, falls on `put_link` resume). Capped at [`MAX_NESTED_LINKS`].
    pub depth: u32,
    /// Linux `nd->total_link_count` — TOTAL symlinks followed in this
    /// resolution (monotonic, never decremented). Capped at
    /// [`MAX_SYMLINK_DEPTH`] (`MAXSYMLINKS` = 40) — the cycle guard.
    pub total_link_count: u32,
    pub flags: LookupFlags,
    pub cred: Cred,
    /// LOOKUP_RCU live state (Linux `nd->flags & LOOKUP_RCU`). Seeded from
    /// `flags.rcu`; CLEARED by `unlazy_walk` (legitimized → ref walk) or by
    /// `terminate_walk` (error/teardown exit). Persists across a bounded
    /// rename-seqretry restart so a still-lazy walk re-attempts in rcu mode;
    /// a fallback restart clears it so the retry is a plain ref walk.
    pub rcu: bool,
}

/// Bounded number of whole-walk restarts (Linux retries the lock-free walk a
/// bounded number of times before falling to the ref walk). On exhaustion the
/// walk PROCEEDS with the Arc-walk result (seqretries ignored) — the `Arc`
/// already guarantees memory safety, so this bounded-degrade valve can never
/// livelock the walk (the apex boot-safety property of the D22 work).
const MAX_WALK_RESTARTS: u32 = 16;

/// One pass of the component walk either RESOLVED a final `VfsPath`, or hit a
/// rename-seqretry / rcu-legitimize failure that demands a bounded RESTART
/// (Linux `retry_estale` / `try_to_unlazy` failure → re-walk).
pub(crate) enum WalkOutcome { Done(VfsPath), Restart }

impl Nameidata {
    /// Build the walk state from a `start` (dirfd/cwd base) and a resolution
    /// `root`. Both are normalised through any mountpoint they sit on (Linux
    /// holds `(vfsmount, dentry)`; a covered base resolves inside the mounted
    /// fs). # C: O(start/root mount stack)
    pub fn new(start: Arc<Dentry>, root: Arc<Dentry>, flags: LookupFlags, cred: Cred) -> KResult<Self> {
        let ns = crate::mount::current_ns();
        // Seed each follow-down with the mount that CONTAINS the base dentry, not
        // the ns-root mount. The caller hands bare dentries (no `vfsmount`); a
        // base sitting inside a sub-mount (chroot/pivot staging dir) lives in that
        // sub-mount, not the root, so `__lookup_mnt(cur_mnt_id, d)` must key on the
        // true containing mount for the crossing to resolve. The seed `mnt_id` the
        // walk carries is the design linchpin — ns-correctness flows from
        // `cur_mnt_id` through the `(parent_mnt_id, dentry)` strict hash.
        let root_base = crate::mount::containing_mount_id(ns, &root);
        let (mut root_dentry, _ri, mut root_mnt_id) = follow_mount_down(root, root_base)?;
        let start_base = crate::mount::containing_mount_id(ns, &start);
        let (cur_dentry, cur_inode, cur_mnt_id) = follow_mount_down(start, start_base)?;
        // RESOLVE_IN_ROOT (openat2): the dirfd (START) becomes the resolution
        // root, so `to_root()` (absolute paths / absolute symlink restarts) and
        // `dotdot_step` (`..` clamp) all confine to it, overriding the passed
        // `root` (Linux sets `nd->root = nd->path` for LOOKUP_IS_SCOPED+IN_ROOT).
        // RESOLVE_BENEATH (`beneath_exdev`) likewise scopes resolution to the
        // dirfd, but ERRORS on escape (handled in `walk`) instead of clamping.
        if flags.in_root || flags.beneath_exdev { root_dentry = cur_dentry.clone(); root_mnt_id = cur_mnt_id; }
        let rcu = flags.rcu;
        Ok(Nameidata { cur_mnt_id, cur_dentry, cur_inode, root_mnt_id, root_dentry, depth: 0, total_link_count: 0, flags, cred, rcu })
    }

    /// Build the walk state for an `*at` resolution whose `start`/`root` arrive
    /// WITH their real mount ids (the dirfd `File` carries `f.mnt_id()`; the cwd
    /// `VfsPath` carries `mnt_id`). Unlike [`Nameidata::new`], this SKIPS the
    /// `containing_mount_id` guess — the caller already knows the mount the base
    /// lives in (the file was opened through it), so the seed `mnt_id` is the
    /// exact mount, not a region-containment best-guess. This is what makes a
    /// dirfd that names a BIND mount resolve relative paths (and `..`) through
    /// the bind's own mount identity instead of the canonical mount the
    /// stringified `absolute_path()` would re-resolve to (D17 / dcache D16). Both
    /// ids are still normalised through any over-mount via `follow_mount_down`.
    /// # C: O(start/root mount stack)
    pub fn new_at(
        start: Arc<Dentry>, start_mnt_id: u64,
        root: Arc<Dentry>, root_mnt_id: u64,
        flags: LookupFlags, cred: Cred,
    ) -> KResult<Self> {
        let (mut root_dentry, _ri, mut root_mnt_id) = follow_mount_down(root, root_mnt_id)?;
        let (cur_dentry, cur_inode, cur_mnt_id) = follow_mount_down(start, start_mnt_id)?;
        // RESOLVE_IN_ROOT / RESOLVE_BENEATH: the dirfd (START) IS the resolution
        // root (same override as `new`).
        if flags.in_root || flags.beneath_exdev { root_dentry = cur_dentry.clone(); root_mnt_id = cur_mnt_id; }
        let rcu = flags.rcu;
        Ok(Nameidata { cur_mnt_id, cur_dentry, cur_inode, root_mnt_id, root_dentry, depth: 0, total_link_count: 0, flags, cred, rcu })
    }

    /// Reset the current position to the resolution root (absolute path /
    /// absolute symlink target). # C: O(1)
    pub(super) fn to_root(&mut self) -> KResult<()> {
        self.cur_dentry = self.root_dentry.clone();
        self.cur_mnt_id = self.root_mnt_id;
        self.cur_inode = self.cur_dentry.inode().ok_or(VfsError::Enoent)?;
        Ok(())
    }

    /// `..` — `follow_dotdot` clamped at the resolution root. Returns `true`
    /// when the step was an escape attempt clamped at the root (the caller
    /// turns this into `EXDEV` under `beneath_exdev`). # C: O(stack)
    pub(super) fn handle_dotdot(&mut self) -> bool {
        dotdot_step(
            &mut self.cur_dentry, &mut self.cur_mnt_id, &mut self.cur_inode,
            &self.root_dentry, self.root_mnt_id,
        )
    }

    /// `terminate_walk` (Linux `fs/namei.c`) — the SINGLE error/teardown exit
    /// of the walk. In the default ref/Arc walk the resolver pins NOTHING via
    /// `d_count` (the `Arc` in `cur_dentry` is the only hold and drops on
    /// return), so the body is the rcu-mode unwind: leave LOOKUP_RCU
    /// (`nd->flags &= ~LOOKUP_RCU`) so any restart begins as a clean ref walk
    /// and no lazy read-side leaks out of the failed resolution. Returns `e`
    /// unchanged so every error site funnels through one exit
    /// (`Err(self.terminate_walk(e))`). D28: lands the single-exit plumbing —
    /// load-bearing once a real rcu read-side / saved-link `d_count` stack is
    /// held (Step C / a later lane); a no-op net effect on the Arc walk today.
    /// # C: O(1)
    pub(super) fn terminate_walk(&mut self, e: VfsError) -> VfsError {
        self.rcu = false;
        e
    }

    /// `unlazy_walk` / `try_to_unlazy` (Linux `fs/namei.c`) — leave LOOKUP_RCU
    /// at a point that must block or take a lock (symlink `get_link`, mount
    /// crossing, the final component, a blocking permission check, or a dcache
    /// miss that needs `i_op->lookup` under `i_rwsem`). LEGITIMIZE the freshly
    /// resolved `child`: pin it (`inc_count_not_zero`) THEN re-validate the
    /// per-dentry (`cseq`) and global (`m_seq`) rename seqcounts — the
    /// reference-BEFORE-recheck order. On success drop rcu mode and continue as
    /// a ref/Arc walk (the `Arc` is the durable hold; the transient pin was
    /// only the not-zero legitimize test, released here). On ANY failure return
    /// `false` so the caller restarts the walk in ref mode (`self.rcu` is left
    /// cleared). In this lane's Arc-walk substrate the dcache `d_count` is
    /// DORMANT (an unheld cache dentry rests at 0 — the dput/dget lockref
    /// lifecycle is built-but-unwired, dcache D11), so `inc_count_not_zero`
    /// conservatively fails and rcu mode legitimizes by FALLING BACK to the
    /// proven ref walk at the first complication — provably == the Arc walk.
    /// # C: O(1)
    pub(super) fn unlazy_walk(&mut self, child: &Arc<Dentry>, cseq: u32, m_seq: u32) -> bool {
        if !self.rcu { return true; }
        // EVERY failure path leaves LOOKUP_RCU (the fallback IS dropping rcu),
        // so the caller's restart re-walks as a plain ref walk and can never
        // re-enter rcu to fail again — the termination guarantee of the
        // fast-path overlay (a missed `self.rcu` clear here is an infinite
        // restart). The legitimize succeeds only when the pin AND both
        // seqcounts hold; otherwise fall back.
        self.rcu = false;
        if !child.inc_count_not_zero() { return false; }
        let raced = child.read_seqretry(cseq) || crate::dcache::rename_lock_retry(m_seq);
        child.dec_count(); // Arc pins; the bump was only the not-zero legitimize test
        !raced
    }

    /// Resolve `path` from the current state to a final `VfsPath`. Drives a
    /// BOUNDED restart loop over [`walk_inner`]: a rename raced mid-walk (the
    /// D22 per-component `d_seq` / global `rename_lock` seqretry) or an rcu
    /// legitimize failure restarts the walk from the snapshotted start, up to
    /// [`MAX_WALK_RESTARTS`]; on exhaustion a final un-validated pass PROCEEDS
    /// with the Arc-walk result (the bounded-degrade valve — cannot livelock).
    /// All errors exit through the single [`terminate_walk`]. # C:
    /// O(restarts × components × dir-lookup) + O(symlinks)
    pub fn walk(&mut self, path: &str) -> KResult<VfsPath> {
        // Snapshot the start position so a restart re-walks from scratch.
        let s_mnt = self.cur_mnt_id;
        let s_dentry = self.cur_dentry.clone();
        let s_inode = self.cur_inode.clone();
        let mut attempt = 0u32;
        loop {
            let validate = attempt < MAX_WALK_RESTARTS;
            match self.walk_inner(path, validate) {
                Ok(WalkOutcome::Done(p)) => return Ok(p),
                Ok(WalkOutcome::Restart) => {
                    attempt += 1;
                    self.cur_mnt_id = s_mnt;
                    self.cur_dentry = s_dentry.clone();
                    self.cur_inode = s_inode.clone();
                    self.depth = 0;
                    self.total_link_count = 0;
                    // `self.rcu` persists (a seqretry restart re-attempts lazily);
                    // a fallback restart already cleared it in `unlazy_walk`.
                    continue;
                }
                Err(e) => return Err(self.terminate_walk(e)),
            }
        }
    }
}
