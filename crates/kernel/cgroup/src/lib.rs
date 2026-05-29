// cgroup v2 unified hierarchy per `26§4`. Single tree mounted at
// `/sys/fs/cgroup`; controllers cpu/memory/io/pids/cpuset. This crate
// owns the hierarchy state (`tree`) + the VFS bridge (`inode`); the
// kernel wires the sched↔cgroup glue (fork inheritance, signal
// delivery for cgroup.kill, `/proc/<pid>/cgroup`) via the hooks here,
// keeping this a leaf crate (no sched dependency → no cycle).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod inode;
pub mod tree;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use alloc::sync::Arc;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::fs::FileSystem;
use vfs::{InodeRef, KResult, VfsError};

use tree::Tree;

/// cgroup2 filesystem for the unified mount table (`16§7`). Mounted
/// at `/sys/fs/cgroup`; `vfs::mount::lookup` routes paths here. v1
/// backends key by full absolute path, so `lookup` delegates to the
/// devfs registry where `mount_root`/`mkdir_child` register the
/// CgDir/CgFile inodes.
pub struct CgroupFs;

impl FileSystem for CgroupFs {
    /// # C: O(1)
    fn name(&self) -> &str { "cgroup2" }
    /// # C: O(N devfs registry)
    fn lookup(&self, path: &str) -> Option<InodeRef> { devfs::lookup(path) }
    /// # C: O(1)
    fn mounts_line(&self, mp: &str) -> alloc::string::String {
        let mut s = alloc::string::String::from("cgroup2 ");
        s.push_str(mp);
        s.push_str(" cgroup2 rw,nosuid,nodev,noexec,relatime 0 0\n");
        s
    }
}

/// SIGKILL — raw number (the typed `Signum` lives in `sched`, which
/// this leaf crate cannot depend on without a cycle). Delivered via
/// the registered `SIGNAL_HOOK` for `cgroup.kill`.
const SIGKILL: i32 = 9;

static TREE: Spinlock<Tree, TaskListClass> = Spinlock::new(Tree::new());

/// Signal-delivery hook: `fn(pid, signum)`. Set by the kernel at
/// boot so `cgroup.kill` can SIGKILL every member without this crate
/// depending on `sched`.
static SIGNAL_HOOK: Spinlock<Option<fn(u64, i32)>, TaskListClass> = Spinlock::new(None);

/// Mount-point of the unified hierarchy.
pub const MOUNT: &str = "/sys/fs/cgroup";

/// Install the signal hook. Boot path.
/// # C: O(1)
pub fn set_signal_hook(f: fn(u64, i32)) { *SIGNAL_HOOK.lock() = Some(f); }

/// Mount the unified hierarchy: create the root node and register its
/// directory + core control files in devfs. Idempotent (re-mount is a
/// no-op success). Returns true on the first mount.
/// # C: O(1)
pub fn mount_root() -> bool {
    let first = TREE.lock().mount_root();
    if first {
        let rows = inode::build_inodes(tree::ROOT, MOUNT, tree::ALL, true);
        for (p, ino) in rows { devfs::register_owned(p, ino); }
        // Route /sys/fs/cgroup/* through CgroupFs in the unified mount
        // table so open()/read/write reach these inodes (`16§7`).
        let _ = vfs::mount::register(MOUNT, Arc::new(CgroupFs));
    }
    first
}

/// True once `/sys/fs/cgroup` is mounted.
/// # C: O(1)
pub fn is_mounted() -> bool { TREE.lock().is_mounted() }

/// Read a control file `(cgid, file)`.
/// # C: O(subtree) for populated/pids; O(members) for procs
pub fn read_file(cgid: u64, file: &str) -> KResult<Vec<u8>> {
    TREE.lock().read_file(cgid, file)
}

/// Write a control file. Handles the cross-subsystem files
/// (cgroup.procs/threads/subtree_control/kill/freeze) here; delegates
/// per-controller limit files to the tree.
/// # C: O(tokens) + O(members) for kill
pub fn write_file(cgid: u64, file: &str, buf: &str) -> KResult<()> {
    match file {
        "cgroup.procs" | "cgroup.threads" => {
            let pid: u64 = buf.trim().parse().map_err(|_| VfsError::Einval)?;
            TREE.lock().add_proc(cgid, pid);
            Ok(())
        }
        "cgroup.subtree_control" => {
            let (old, new) = {
                let mut t = TREE.lock();
                let old = t.node(cgid).map(|n| n.subtree_control).unwrap_or(0);
                let new = t.write_subtree_control(cgid, buf)?;
                (old, new)
            };
            if old != new { sync_children_controller_files(cgid, old, new); }
            Ok(())
        }
        "cgroup.kill" => {
            if buf.trim() != "1" { return Err(VfsError::Einval); }
            let pids = TREE.lock().subtree_pids(cgid);
            if let Some(hook) = *SIGNAL_HOOK.lock() {
                for p in pids { hook(p, SIGKILL); }
            }
            Ok(())
        }
        "cgroup.freeze" => {
            let v = match buf.trim() { "1" => true, "0" => false, _ => return Err(VfsError::Einval) };
            TREE.lock().set_frozen(cgid, v);
            Ok(())
        }
        _ => TREE.lock().write_file(cgid, file, buf),
    }
}

/// `mkdir(2)` on a cgroup directory: create the child node and
/// register its dir + control files. Returns the new dir inode.
/// Full devfs path of a cgroup node: `MOUNT` + the hierarchy path
/// (`tree::path_of` yields `/a/b`, the devfs registry keys on the
/// mount-prefixed `/sys/fs/cgroup/a/b`). Root maps to `MOUNT`.
/// # C: O(depth)
fn fs_path(t: &Tree, cgid: u64) -> String {
    let hp = t.path_of(cgid);
    if hp == "/" { return String::from(MOUNT); }
    let mut s = String::from(MOUNT);
    s.push_str(&hp);
    s
}

/// # C: O(files)
pub fn mkdir_child(parent_cgid: u64, parent_path: &str, name: &str) -> KResult<InodeRef> {
    let (id, avail) = TREE.lock().create(parent_cgid, name)?;
    let mut path = String::from(parent_path);
    if !path.ends_with('/') { path.push('/'); }
    path.push_str(name);
    let rows = inode::build_inodes(id, &path, avail, false);
    let dir = rows.first().map(|(_, i)| i.clone());
    for (p, ino) in rows { devfs::register_owned(p, ino); }
    dir.ok_or(VfsError::Eio)
}

/// `rmdir(2)` on a cgroup directory: remove the (empty) child node and
/// unregister its dir + files from devfs.
/// # C: O(registry)
pub fn rmdir_child(parent_cgid: u64, name: &str) -> KResult<()> {
    let (id, path) = {
        let t = TREE.lock();
        let cid = *t.node(parent_cgid).ok_or(VfsError::Enoent)?
            .children.get(name).ok_or(VfsError::Enoent)?;
        (cid, fs_path(&t, cid))
    };
    TREE.lock().remove(id)?;
    devfs::unregister_subtree(0, &path);
    Ok(())
}

/// Add/remove controller interface files on a node's existing children
/// when the parent's subtree_control changes availability.
fn sync_children_controller_files(parent: u64, old: u8, new: u8) {
    let kids: Vec<(u64, String)> = {
        let t = TREE.lock();
        match t.node(parent) {
            Some(n) => n.children.values().map(|&c| (c, fs_path(&t, c))).collect(),
            None => return,
        }
    };
    let added = new & !old;
    let removed = old & !new;
    for (cid, cpath) in kids {
        if removed != 0 {
            for f in tree::controller_files(removed) {
                let mut fp = cpath.clone(); fp.push('/'); fp.push_str(f);
                devfs::unregister_subtree(0, &fp);
            }
        }
        if added != 0 {
            let mut seq = (cid << 8) + 0x80;
            for f in tree::controller_files(added) {
                let mut fp = cpath.clone(); fp.push('/'); fp.push_str(f);
                devfs::register_owned(fp, alloc::sync::Arc::new(
                    inode::CgFile::new(cid, f, seq)) as InodeRef);
                seq += 1;
            }
        }
    }
}

// --- sched glue ----------------------------------------------------

/// True iff forking one more task in `cgid`'s subtree would exceed an
/// ancestor `pids.max` (the kernel returns EAGAIN). Defaults to the
/// task's current cgroup; root is unlimited.
/// # C: O(depth · subtree)
pub fn fork_would_exceed_pids(pid: u64) -> bool {
    let t = TREE.lock();
    if !t.is_mounted() { return false; }
    let cg = t.cgroup_of(pid);
    t.fork_would_exceed_pids(cg)
}

/// Child inherits the parent's cgroup on fork.
/// # C: O(log n)
pub fn inherit(child_pid: u64, parent_pid: u64) {
    let mut t = TREE.lock();
    if !t.is_mounted() { return; }
    let cg = t.cgroup_of(parent_pid);
    t.add_proc(cg, child_pid);
}

/// Drop a process from its cgroup on exit.
/// # C: O(log n)
pub fn on_exit(pid: u64) {
    let mut t = TREE.lock();
    if t.is_mounted() { t.remove_proc(pid); }
}

/// `/proc/<pid>/cgroup` line — `0::<path>\n` for the unified
/// hierarchy (Linux format; controller field empty for v2).
/// # C: O(depth)
pub fn proc_cgroup(pid: u64) -> String {
    let t = TREE.lock();
    if !t.is_mounted() { return "0::/\n".to_string(); }
    let cg = t.cgroup_of(pid);
    let mut s = String::from("0::");
    s.push_str(&t.path_of(cg));
    s.push('\n');
    s
}

#[cfg(test)]
mod tests;
