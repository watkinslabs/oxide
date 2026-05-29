# VFS + cgroup v2 Implementation Map for oxide2

**Date:** 2026-05-29  
**Scope:** Filesystem trait hierarchy, pseudo-FS dynamic file patterns, Task namespace slots, cgroup v2 registration point.

---

## 1. VFS Core Traits & Signatures

### 1.1 FileSystem trait (Mount-level registration)

**File:** `/home/nd/oxide2/crates/kernel/vfs/src/fs.rs` (lines 22–68)

```rust
pub trait FileSystem: Send + Sync {
    /// Human-readable FS-type name. "ext4", "tmpfs", "devfs", "procfs".
    /// # C: O(1)
    fn name(&self) -> &str;

    /// Resolve path (relative to this FS's mount point) to InodeRef.
    /// Returns None if no such name exists.
    /// # C: depends on FS — typically O(path-component-count).
    fn lookup(&self, path: &str) -> Option<InodeRef>;

    /// Create a new regular file at path with permission mode.
    /// Default: returns Erofs.
    /// # C: depends on FS.
    fn create(&self, path: &str, mode: u32) -> KResult<InodeRef> { ... }

    /// Remove the regular file at path. Default: Erofs.
    /// # C: depends on FS.
    fn unlink(&self, path: &str) -> KResult<()> { ... }

    /// Rename from to to. Both paths relative to this FS.
    /// Default: Erofs.
    /// # C: depends on FS.
    fn rename(&self, from: &str, to: &str) -> KResult<()> { ... }

    /// /proc/mounts-style description: "<src> <mnt> <fstype> <opts>".
    /// # C: O(1)
    fn mounts_line(&self, mount_point: &str) -> String { ... }
}
```

**Type alias:**
```rust
pub type InodeRef = Arc<dyn Inode>;
pub type KResult<T> = core::result::Result<T, VfsError>;
```

**ERROR ENUM:**
```rust
enum VfsError {
    Enoent, Eperm, Eisdir, Enotdir, Eexist, Erofs, Eagain, Einval, Enospc, Eio, ...
}
```

### 1.2 Inode trait (Per-file interface)

**File:** `/home/nd/oxide2/crates/kernel/vfs/src/inode.rs` (lines 20–173)

```rust
pub trait Inode: Send + Sync {
    /// Optional downcast hook. Returns Some(self) for types needing
    /// recovery from Arc<dyn Inode>. Default: None.
    fn as_any(&self) -> Option<&dyn core::any::Any> { None }

    /// # C: O(1)
    fn ino(&self) -> Ino;

    /// # C: O(1)
    fn file_type(&self) -> FileType;  // Regular, Directory, Symlink, CharDev, BlockDev, ...

    /// # C: O(1)
    fn size(&self) -> u64;

    /// Resolve name within this inode (must be a directory).
    /// Returns Err(Enotdir) for non-dirs; Err(Enoent) for missing names.
    /// # C: depends on FS impl
    fn lookup(&self, name: &str) -> KResult<InodeRef>;

    /// Read into buf starting at byte offset off.
    /// Returns number of bytes read; 0 indicates EOF.
    /// Default: Err(Eisdir) for directories.
    /// # C: depends on FS impl
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> { Err(VfsError::Eisdir) }

    /// Non-blocking read variant (O_NONBLOCK). Default delegates to read().
    fn read_nonblock(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read(off, buf)
    }

    /// Non-blocking write variant (O_NONBLOCK). Default delegates to write().
    fn write_nonblock(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write(off, buf)
    }

    /// Write buf starting at byte offset off.
    /// Default: Err(Eisdir).
    /// # C: depends on FS impl
    fn write(&self, off: u64, buf: &[u8]) -> KResult<usize> { Err(VfsError::Eisdir) }

    /// Resolve a symbolic link to its target path bytes.
    /// Default: Err(Einval) for non-symlinks.
    fn readlink(&self) -> KResult<Vec<u8>> { Err(VfsError::Einval) }

    /// Truncate the file to len bytes.
    /// Default: Erofs.
    fn truncate(&self, len: u64) -> KResult<()> { Err(VfsError::Erofs) }

    /// Iterate child entries of a directory.
    /// off is the cookie from previous call; 0 starts from beginning.
    /// Callback returns false to stop early.
    /// Default: Err(Enotdir).
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> { Err(VfsError::Enotdir) }

    /// Non-blocking readiness query. Bitmask of POLL_* flags.
    /// Default: POLL_IN | POLL_OUT (always ready).
    fn poll(&self) -> u32 { POLL_IN | POLL_OUT }

    /// Per-Inode subscriber list for targeted epoll wakes.
    /// Default: None (falls back to global epoll-broadcast).
    fn poll_subscribers(&self) -> Option<&crate::PollSubscribers> { None }

    /// Per-FS metadata accessors. Return None to fall through to overlay/statx.
    fn mtime(&self) -> Option<u64> { None }
    fn atime(&self) -> Option<u64> { None }
    fn ctime(&self) -> Option<u64> { None }

    /// Update atime/mtime/ctime. None field = leave alone (UTIME_OMIT).
    fn set_times(&self, atime: Option<u64>, mtime: Option<u64>, ctime: u64) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// Permission bits — low 12 bits of mode. None = no override.
    fn perm(&self) -> Option<u16> { None }
    fn uid(&self) -> Option<u32> { None }
    fn gid(&self) -> Option<u32> { None }

    /// chmod(2) backend. Default: Erofs.
    fn set_perm(&self, perm: u16) -> KResult<()> { Err(VfsError::Erofs) }

    /// chown(2) backend. Default: Erofs.
    fn set_owner(&self, uid: u32, gid: u32) -> KResult<()> { Err(VfsError::Erofs) }
}

pub const POLL_IN:    u32 = 0x0001;  // POLLIN  — readable
pub const POLL_OUT:   u32 = 0x0004;  // POLLOUT — writable
pub const POLL_HUP:   u32 = 0x0010;  // POLLHUP — peer closed
pub const POLL_ERR:   u32 = 0x0008;  // POLLERR — io error
pub const POLL_PRI:   u32 = 0x0002;  // POLLPRI — urgent (TCP OOB)
pub const POLL_RDHUP: u32 = 0x2000;  // POLLRDHUP — peer-closed-write
```

---

## 2. Pseudo-FS Primitive: Dynamic File Pattern (procfs model)

**File:** `/home/nd/oxide2/crates/kernel/procfs/src/pseudo.rs` (lines 36–258)

### 2.1 PseudoOps trait (Read/write callbacks)

```rust
pub trait PseudoOps: Send + Sync {
    /// Read callback: snapshot data per invariant 4 (19§2).
    /// # C: depends on producer
    fn read(&self) -> Vec<u8>;

    /// Write callback: optional (read-only default returns Eperm).
    /// # C: depends on producer
    fn write(&self, buf: &[u8]) -> KResult<usize> {
        Err(PseudoError::Eperm)
    }
}
```

### 2.2 PseudoLeaf (Concrete file node)

```rust
pub struct PseudoLeaf {
    pub name: String,
    pub mode: u32,                  // u32 permission bits
    pub ops:  Arc<dyn PseudoOps>,   // Callback handler
}
```

### 2.3 Static-backed ops (constant files)

```rust
pub struct StaticBytesOps(pub &'static [u8]);

impl PseudoOps for StaticBytesOps {
    fn read(&self) -> Vec<u8> { self.0.to_vec() }
}
```

### 2.4 Dynamic-backed ops (computed on every read)

```rust
pub struct DynamicOps<F>(pub F)
where
    F: Fn() -> Vec<u8> + Send + Sync + 'static;

impl<F> PseudoOps for DynamicOps<F>
where
    F: Fn() -> Vec<u8> + Send + Sync + 'static,
{
    fn read(&self) -> Vec<u8> { (self.0)() }
}
```

### 2.5 PseudoFs container

```rust
pub struct PseudoFs {
    inner: RwLock<PseudoDir, InodeClass>,  // Single RwLock guards entire tree
}

impl PseudoFs {
    pub const fn new() -> Self { ... }

    /// Create directory hierarchy at path (idempotent).
    /// # C: O(components)
    pub fn mkdir(&self, path: &str) -> KResult<()> { ... }

    /// Install leaf at parent_path/leaf.name. Parent must exist.
    /// # C: O(components)
    pub fn register(&self, parent_path: &str, leaf: PseudoLeaf) -> KResult<()> { ... }

    /// Snapshot the leaf at path and call its read.
    /// # C: O(components) plus read cost
    pub fn read(&self, path: &str) -> KResult<Vec<u8>> { ... }

    /// Forward write to the leaf at path.
    /// # C: O(components) plus write cost
    pub fn write(&self, path: &str, buf: &[u8]) -> KResult<usize> { ... }

    /// List entries at path (names only, sorted).
    /// # C: O(components + N) where N = entries at dir
    pub fn list(&self, path: &str) -> KResult<Vec<String>> { ... }

    /// True iff path resolves to existing entry (leaf or directory).
    /// # C: O(components)
    pub fn exists(&self, path: &str) -> bool { ... }
}
```

### 2.6 Example: /proc/self/* dynamic inodes (kernel/src/procfs/mod.rs)

**ProcSelfMapsInode** (lines 50–110):
```rust
pub struct ProcSelfMapsInode;

impl ProcSelfMapsInode {
    fn body() -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        let cur = match sched::live::current() { Some(c) => c, None => return out };
        // SAFETY: running task on this CPU; preempt-off; sole reader of mm
        let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return out };
        for vma in mm.snapshot_vmas() {
            push_hex(&mut out, vma.start.as_u64());
            out.push(b'-');
            push_hex(&mut out, vma.end.as_u64());
            out.push(b' ');
            // perms: rwx + p/s
            let p = vma.prot;
            out.push(if p.contains(vmm::VmaProt::READ)  { b'r' } else { b'-' });
            out.push(if p.contains(vmm::VmaProt::WRITE) { b'w' } else { b'-' });
            out.push(if p.contains(vmm::VmaProt::EXEC)  { b'x' } else { b'-' });
            out.push(if vma.flags.contains(vmm::VmaFlags::SHARED) { b's' } else { b'p' });
            push(&mut out, b" 00000000 00:00 0 ");
            if vma.flags.contains(vmm::VmaFlags::GROWSDOWN) {
                push(&mut out, b"[stack]");
            } else if is_brk_range(vma, brk_hi) {
                push(&mut out, b"[heap]");
            }
            out.push(b'\n');
        }
        out
    }
}

impl Inode for ProcSelfMapsInode {
    fn ino(&self) -> Ino { 0x3000_1300 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = Self::body();
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let avail = &body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    fn write(&self, _o: u64, _b: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}
```

---

## 3. fstype Registration: Mount Syscall

**File:** `/home/nd/oxide2/kernel/src/syscalls/mount.rs` (lines 28–62)

### 3.1 sys_mount implementation

```rust
/// sys_mount(source, target, fstype, flags, data) — slot 165.
/// V1 honours fstype="tmpfs" by spawning a fresh TmpfsRootInode at
/// target in devfs. Other fstypes return EOPNOTSUPP. Requires CAP_SYS_ADMIN.
/// # C: O(N_path)
pub fn sys_mount(args: &SyscallArgs) -> i64 {
    let _source   = args.a0;
    let target_p  = args.a1;
    let fstype_p  = args.a2;
    let _flags    = args.a3;
    let _data     = args.a4;

    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }

    let target = match read_user_cstr_owned(target_p, 256) { 
        Ok(s) => s, Err(rv) => return rv 
    };
    let fstype = match read_user_cstr_owned(fstype_p, 32) { 
        Ok(s) => s, Err(rv) => return rv 
    };

    if !target.starts_with('/') {
        return -(Errno::Einval.as_i32() as i64);
    }

    match fstype.as_str() {
        "tmpfs" => {
            let inode: InodeRef = Arc::new(::fs::tmpfs::TmpfsRootInode::new(target.clone()));
            let ns = cur.mount_ns.load(core::sync::atomic::Ordering::Acquire);
            crate::devfs::register_in_ns(ns, target, inode);
            0
        }
        // Admit-and-noop for already-registered pseudo-FSes so userspace
        // remount probes (systemd, /etc/mtab tooling) don't choke:
        "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup" | "cgroup2" => 0,
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}
```

**KEY POINT:** Line 59 admits `"cgroup"` and `"cgroup2"` as noops. Real mount logic would:
1. Parse fstype string → find driver entry
2. Call `driver.mount(source, target, opts)` → get inode
3. Register inode in current task's mount_ns via `register_in_ns()`

---

## 4. Devfs Registry: Static registration point

**File:** `/home/nd/oxide2/kernel/src/devfs.rs` (lines 1–73)

### 4.1 Boot-time registration

```rust
/// Boot-time devfs population per docs/19. Registers v1 console + tty char devices.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    let fg: InodeRef = Arc::new(crate::dev::console::ConsoleInode::new(0));
    register("/dev/console", Arc::clone(&fg));
    register("/dev/tty",     Arc::clone(&fg));
    register("/dev/tty0",    Arc::clone(&fg));
    register("/dev/ttyS0",   fg);

    for vt in 1..=tty::live::N_VT as u8 {
        let mut path = String::with_capacity(10);
        path.push_str("/dev/tty");
        if vt >= 10 { path.push((b'0' + (vt / 10)) as char); }
        path.push((b'0' + (vt % 10)) as char);
        let inode: InodeRef = Arc::new(crate::dev::console::ConsoleInode::new(vt));
        register_owned(path, inode);
    }

    register("/dev/null",    Arc::new(devfs::misc::NullInode)   as InodeRef);
    register("/dev/kmsg",    Arc::new(devfs::misc::KmsgInode)   as InodeRef);
    register("/dev/log",     Arc::new(devfs::misc::NullInode)   as InodeRef);
    register("/dev/zero",    Arc::new(devfs::misc::ZeroInode)   as InodeRef);
    register("/dev/full",    Arc::new(devfs::misc::FullInode)   as InodeRef);
    let rand: InodeRef = Arc::new(devfs::misc::RandomInode);
    register("/dev/random",  Arc::clone(&rand));
    register("/dev/urandom", rand);

    // Synthetic directories (register after leaves so they enumerate correctly)
    register_dir("/",         0x5000_0001);
    register_dir("/dev",      0x5000_0002);
    register_dir("/sys",      0x5000_0003);
    register_dir("/etc",      0x5000_0004);
    register_dir("/bin",      0x5000_0005);
    register_dir("/usr",      0x5000_0006);
    register_dir("/usr/bin",  0x5000_0007);
    register_dir("/proc/sys", 0x5000_0008);
}

fn register_dir(path: &'static str, ino: Ino) {
    register(path, Arc::new(PrefixDirInode { prefix: path, ino }) as InodeRef);
}
```

### 4.2 Re-exported crate::devfs API

```rust
// From line 18–21: re-exports of crates/devfs surface
pub use ::devfs::{
    lookup,
    read_user_cstr,
    register,
    register_in_ns,
    register_owned,
    snapshot_ns,
    snapshot_visible_to_current,
    unregister_subtree,
};
```

---

## 5. Task Namespace & cgroup slots

**File:** `/home/nd/oxide2/crates/kernel/sched/src/task.rs` (lines 318–460)

### 5.1 Per-task namespace IDs

```rust
pub struct Task {
    // ... other fields ...

    /// Per-task namespace membership bitmap. Bit i set ⇔ this task
    /// has its own slot for namespace i (rather than inheriting init-NS).
    /// Bit assignments mirror Linux CLONE_NEW*:
    ///   bit  0 = NEWNS    (mount)        | CLONE_NEWNS    = 0x00020000
    ///   bit  1 = NEWUTS   (uts)          | CLONE_NEWUTS   = 0x04000000
    ///   bit  2 = NEWIPC   (ipc)          | CLONE_NEWIPC   = 0x08000000
    ///   bit  3 = NEWUSER  (user)         | CLONE_NEWUSER  = 0x10000000
    ///   bit  4 = NEWPID   (pid)          | CLONE_NEWPID   = 0x20000000
    ///   bit  5 = NEWNET   (net)          | CLONE_NEWNET   = 0x40000000
    ///   bit  6 = NEWCGROUP (cgroup)                       = 0x02000000
    /// # C: O(1)
    pub ns_membership: AtomicU64,

    /// Per-NS UTS hostname when bit 1 of ns_membership is set.
    /// Empty string means "inherit from global".
    pub uts_hostname: UnsafeCell<String>,

    /// IPC namespace id (CLONE_NEWIPC). Default 0 (init NS).
    /// SysV shm/sem/msg + POSIX MQ tables are virtualised by this id.
    pub ipc_ns: AtomicU64,

    /// Net namespace id (CLONE_NEWNET). Default 0 (init NS).
    /// IfaceRegistry filters by this id.
    pub net_ns: AtomicU64,

    /// PID namespace id (CLONE_NEWPID). Default 0 (init NS).
    pub pid_ns: AtomicU64,
    pub vtgid:  AtomicU32,  // Virtualised tgid seen from this task's pid_ns
    pub vtid:   AtomicU32,  // Virtualised tid (per-thread)
    pub unshare_pid_pending: AtomicBool,

    /// User namespace id (CLONE_NEWUSER). Default 0 (init NS).
    pub user_ns: AtomicU64,
    pub parent_user_ns: AtomicU64,

    /// Cgroup namespace id (CLONE_NEWCGROUP). Default 0 (init NS).
    /// /proc/self/cgroup rebasing is a follow-up (currently flat
    /// single-cgroup hierarchy — every NS sees "0::/" path).
    pub cgroup_ns: AtomicU64,

    /// Mount namespace id (CLONE_NEWNS). Default 0 (init NS).
    pub mount_ns: AtomicU64,
}
```

**NOTE:** There is **no per-task cgroup ID field yet** (line 3 of nscg/src/lib.rs says "cgroup v2 hierarchy walker is a follow-up once the cgroup tree + controllers get wired"). The `cgroup_ns` is the namespace ID; actual cgroup membership tracking is deferred.

---

## 6. nscg crate: Namespace + cgroup stub

**File:** `/home/nd/oxide2/crates/kernel/nscg/src/lib.rs` (lines 1–43)

```rust
// Namespaces + cgroup v2 per `26`.
// Owns the `/proc/<pid>/ns/<type>` real Inode (`NsInode`) and the
// setns/has_cap_for plumbing. Per-task ns id slots themselves live
// on `sched::Task` (uts/ipc/net/pid/user/cgroup/mount); this crate
// is the inode-side surface that bridges userspace fd handles to
// those slots.
//
// cgroup v2 hierarchy walker is a follow-up once the cgroup tree+
// controllers (cpu/memory/pids/io) get wired. v1 ships pid_ns +
// user_ns parent registry only.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod proc_ns;

pub use proc_ns::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS,
    CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS,
    NsInode, NsKind, has_cap_for, ns_inode_for, setns_apply,
};

pub unsafe fn init() -> KResult<()> { Ok(()) }
```

**Cargo.toml dependencies** (lines 10–16):
```toml
[dependencies]
hal     = { path = "../../arch/hal" }
klog    = { path = "../../shared/klog" }
sched   = { path = "../../kernel/sched" }
sync    = { path = "../../shared/sync" }
syscall = { path = "../../kernel/syscall" }
vfs     = { path = "../../kernel/vfs" }
```

---

## 7. procfs static file registrations

**File:** `/home/nd/oxide2/kernel/src/procfs/static_files.rs` (lines 48–56)

### 7.1 Cgroup stub files (v2 single-hierarchy placeholders)

```rust
// cgroup-v2-style stubs. systemd + dbus + login probe both at
// start-up; missing nodes make them fall back through error
// paths or refuse to start. /proc/cgroups header lists no
// controllers (cgroup v2 hides v1 here); /proc/self/cgroup
// returns the v2 single-line "0::/" so the caller's parser
// sees a unified hierarchy with no controller.

crate::devfs::register("/proc/cgroups",
    StaticFileInode::new(b"#subsys_name\thierarchy\tnum_cgroups\tenabled\n") as InodeRef);
crate::devfs::register("/proc/self/cgroup",
    StaticFileInode::new(b"0::/\n") as InodeRef);
```

### 7.2 sysfs stubs (P3-19)

```rust
// /sys hierarchy (P3-19). Same static inode shape; libc/systemd
// probes look these up before falling back.

crate::devfs::register("/sys/kernel/osrelease",
    StaticFileInode::new(b"0.1.0-pre\n") as InodeRef);
crate::devfs::register("/sys/kernel/ostype",
    StaticFileInode::new(b"oxide\n") as InodeRef);
crate::devfs::register("/sys/kernel/random/uuid",
    StaticFileInode::new(b"00000000-0000-0000-0000-000000000001\n") as InodeRef);
crate::devfs::register("/sys/kernel/random/boot_id",
    StaticFileInode::new(b"00000000-0000-0000-0000-000000000002\n") as InodeRef);
// ... etc
```

---

## 8. Feature gating: debug-cgroup pattern

**File:** `/home/nd/oxide2/crates/kernel/sched/Cargo.toml` (lines 34–39)

```toml
[features]
# Per-subsystem debug: gated via `debug-sched` feature flag.
# defaults_features = ["debug-sched", "debug-syscall"]
# forwards via `--features debug-sched`.
debug-sched = []
debug-syscall = []
debug-ssh = []
```

### 8.1 Example usage in kernel crate

**File:** `/home/nd/oxide2/crates/kernel/sched/src/lib.rs` (line 18)

```rust
#[cfg(all(target_os = "oxide-kernel", feature = "debug-sched"))]
extern "C" {
    pub fn kthread_trace(...);
}
```

**Pattern for cgroup v2:** In new `crates/kernel/cgroup/Cargo.toml`:
```toml
[features]
debug-cgroup = []
```

Then in cgroup code:
```rust
#[cfg(all(target_os = "oxide-kernel", feature = "debug-cgroup"))]
fn trace_charge(cgid: u64, bytes: u64) {
    klog!("cgroup {} charged {} bytes", cgid, bytes);
}
```

---

## 9. Recommended cgroup v2 Implementation Path

### 9.1 Crate layout (per docs/52)

**Create:** `/home/nd/oxide2/crates/kernel/cgroup/`

```
crates/kernel/cgroup/
├── Cargo.toml
├── src/
│   ├── lib.rs          (public API + init)
│   ├── tree.rs         (CgroupNode + hierarchy walker)
│   ├── procs.rs        (cgroup.procs / cgroup.threads)
│   ├── controllers.rs   (cpu, memory, io, pids subsystems)
│   ├── sysfs.rs        (/sys/fs/cgroup VFS bridge)
│   └── tests.rs
└── README.md
```

**Cargo.toml:**
```toml
[package]
name = "cgroup"
version = "0.1.0"
edition = "2021"

[dependencies]
sched  = { path = "../../kernel/sched" }
vfs    = { path = "../../kernel/vfs" }
sync   = { path = "../../shared/sync" }
klog   = { path = "../../shared/klog" }
alloc  = { path = "../../shared/alloc" }

[features]
debug-cgroup = []

[lib]
path = "src/lib.rs"
```

### 9.2 Core API surface (trait impls)

**PseudoOps impls for cgroup.procs, memory.max, etc:**

```rust
// Implement per-cgroup-file PseudoOps
pub struct CgroupProcsOps {
    cgroup_id: u64,
}

impl PseudoOps for CgroupProcsOps {
    fn read(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Walk CGROUP_PROCS[self.cgroup_id] task list
        for task in cgroup_tasks(self.cgroup_id) {
            push_u64(&mut out, task.tid as u64);
            out.push(b'\n');
        }
        out
    }

    fn write(&self, buf: &[u8]) -> KResult<usize> {
        let tid = parse_u64(buf)?;
        attach_task_to_cgroup(self.cgroup_id, tid)?;
        Ok(buf.len())
    }
}

pub struct MemoryMaxOps {
    cgroup_id: u64,
}

impl PseudoOps for MemoryMaxOps {
    fn read(&self) -> Vec<u8> {
        let limit = get_cgroup_memory_limit(self.cgroup_id);
        format!("{}\n", limit).into_bytes()
    }

    fn write(&self, buf: &[u8]) -> KResult<usize> {
        let limit = parse_u64(buf)?;
        set_cgroup_memory_limit(self.cgroup_id, limit)?;
        Ok(buf.len())
    }
}
```

### 9.3 VFS registration point

In `/home/nd/oxide2/kernel/src/procfs/static_files.rs`, extend `register_static_files()`:

```rust
// After existing /sys stubs, add:
// /sys/fs/cgroup — root of v2 hierarchy
crate::devfs::register("/sys/fs/cgroup",
    Arc::new(cgroup::sysfs::CgroupRootInode) as InodeRef);

// Dynamic subdirs + control files built by cgroup::sysfs::CgroupDirInode::readdir()
// which walks the kernel's cgroup hierarchy tree and emits directory listings.
```

### 9.4 Task cgroup membership: addition to Task struct

Per `13§5`, add to `struct Task` in `/home/nd/oxide2/crates/kernel/sched/src/task.rs`:

```rust
pub struct Task {
    // ... existing fields ...

    /// Cgroup v2 hierarchy membership (cgroupid). Default 0 (root cgroup).
    /// Per-cgroup CPU weight + memory limit enforcement rides per-CPU
    /// scheduler (CFS weight) + memory allocator (page charge).
    /// # C: O(1)
    pub cgroup_id: AtomicU64,
}
```

Then in `Task::new()` initialization, set `cgroup_id: AtomicU64::new(0)`.

### 9.5 Boot initialization

In `/home/nd/oxide2/kernel_main` (or wherever init sequence is):

```rust
// After devfs::init() and procfs::static_files::register_static_files():
let _ = unsafe { cgroup::init() };  // Initialize cgroup subsystem
```

### 9.6 Mount syscall integration

Modify `/home/nd/oxide2/kernel/src/syscalls/mount.rs` sys_mount:

```rust
match fstype.as_str() {
    // ... existing cases ...
    "cgroup" | "cgroup2" => {
        // Mount cgroup v2 at target
        let inode: InodeRef = Arc::new(cgroup::sysfs::CgroupRootInode::new(target.clone()));
        let ns = cur.mount_ns.load(Ordering::Acquire);
        crate::devfs::register_in_ns(ns, target, inode);
        0
    }
}
```

---

## 10. Summary: Key Signatures & File Locations

| What | Type | File:Line | Signature |
|---|---|---|---|
| **FS registration trait** | `FileSystem` | `crates/kernel/vfs/src/fs.rs:22` | `trait FileSystem: Send+Sync { fn lookup(&self, path) -> Option<InodeRef>; ... }` |
| **Per-file inode trait** | `Inode` | `crates/kernel/vfs/src/inode.rs:20` | `trait Inode: Send+Sync { fn read(&self, off, buf) -> KResult<usize>; fn write(...) -> KResult<usize>; ... }` |
| **Dynamic file callback** | `PseudoOps` | `crates/kernel/procfs/src/pseudo.rs:42` | `trait PseudoOps: Send+Sync { fn read(&self) -> Vec<u8>; fn write(&self, buf) -> KResult<usize>; }` |
| **Mount syscall** | fn | `kernel/src/syscalls/mount.rs:30` | `pub fn sys_mount(args: &SyscallArgs) -> i64` (admits "cgroup"/"cgroup2" as noop at line 59) |
| **Boot devfs init** | fn | `kernel/src/devfs.rs:35` | `pub fn init() { register(...); ... }` |
| **Task namespace slots** | fields | `crates/kernel/sched/src/task.rs:318–460` | `pub cgroup_ns: AtomicU64;` (line 454), plus `mount_ns`, `ipc_ns`, `pid_ns`, `user_ns`, `net_ns` |
| **nscg stub crate** | crate | `crates/kernel/nscg/src/lib.rs:1` | Public API: `NsInode`, `setns_apply`, `has_cap_for` |
| **Feature gating** | toml | `crates/kernel/sched/Cargo.toml:35` | `debug-sched = []` (pattern for `debug-cgroup = []`) |

---

## 11. cgroup v2 File Structure (/sys/fs/cgroup)

```
/sys/fs/cgroup/
├── cgroup.procs              ← List of PIDs + write to move
├── cgroup.threads            ← Thread granularity
├── cgroup.controllers        ← Available controllers
├── cgroup.subtree_control    ← Write to enable/disable per child
├── cgroup.events             ← populated 0/1
├── cgroup.type               ← domain|threaded|domain_invalid
├── cgroup.kill               ← Write 1 to SIGKILL all members
├── cgroup.freeze             ← Freezer
├── cpu.weight                ← CFS weight (100–10000, default 100)
├── cpu.max                   ← <max-us> <period-us> (e.g., "50000 100000")
├── cpu.stat                  ← usage_usec, user_usec, system_usec
├── memory.current            ← Current memory usage (read-only)
├── memory.max                ← Hard limit (write to set)
├── memory.swap.max           ← Swap limit
├── memory.events             ← OOM counter
├── memory.stat               ← Detailed breakdown
├── memory.low                ← Best-effort min
├── memory.high               ← Soft limit
├── memory.pressure           ← PSI metrics
├── io.stat                   ← per-device I/O stats
├── io.max                    ← per-device bandwidth limit
├── io.weight                 ← per-device weight
├── io.latency                ← latency target
├── pids.current              ← Current process count
├── pids.max                  ← Max allowed processes
├── pids.events               ← Max hit counter
├── cpuset.cpus               ← CPU pinning list
├── cpuset.mems               ← NUMA node pinning
│
└── <child-cgroup-names>/     ← Subdirectories for child cgroups
    ├── cgroup.procs          ← Tasks directly in this cgroup
    ├── cgroup.subtree_control
    ├── cpu.weight
    ├── memory.max
    └── ...
```

All files are readable (and writable where specified) via `read(2)` and `write(2)` syscalls through the mounted cgroup v2 filesystem.

---

## 12. Reference: docs/26§4 Frozen cgroup v2 spec

Per `docs/26-namespaces-cgroups.md` lines 119–140:

- **Single tree:** all cgroups in unified `/sys/fs/cgroup/` (no v1 hierarchy)
- **Hierarchy:** directory tree; `mkdir` creates child cgroups
- **Control files:** cgroup.procs, cgroup.threads, cgroup.controllers, cgroup.subtree_control, cgroup.events, cgroup.type, cgroup.kill, cgroup.freeze
- **Controllers:** cpu, memory, io, pids, cpuset (hugetlb, rdma, misc deferred to later phases)
- **Per-controller files:** cpu.weight, cpu.max, cpu.stat; memory.current, memory.max, memory.swap.max, memory.events, memory.stat, memory.low, memory.high, memory.pressure; io.stat, io.max, io.weight, io.latency; pids.current, pids.max, pids.events; cpuset.cpus, cpuset.mems

---

## 13. Test Contract (docs/26§8, §9)

From the spec (frozen):
- Create each ns kind via `unshare`; verify `/proc/<pid>/ns/<kind>` differs from parent
- `setns` re-enters; verify
- pid-ns reaper: kill PID 1 of a pidns; all descendants signaled
- user-ns mapping: rootless task sees uid 0 internally, mapped to nonzero outside
- **Cgroup:** create cgroup, set `memory.max=1MB`, run a task, verify OOM-kill at limit
- Cgroup `cpu.weight` proportional sharing: 2 cgroups @100, @200; verify ~1:2 CPU split under contention
- runc-equivalent shape: spawn container with all namespaces + cgroup limits + seccomp; verify clean exit
- Coverage ≥85%

