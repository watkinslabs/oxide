# 53 Syscall layering

DRAFT (living). Dep: `02`,`08`,`13`,`15`,`42`,`52`.

Architecture for syscall code across crates. `15` defines ABI; this doc owns each
`sys_X` layer.

## 0

Each syscall's handler lives in **its own source file**, named `<NNN>_<name>.rs`,
inside the syscall handler module (the `syscalls` crate). One syscall per FILE —
NOT per crate; this is only a source-file split, never a crate-per-syscall.
- `NNN` = the syscall's **x86_64** number (`15§2` / `nrs::NR_<name>`), zero-padded
  to 3 digits (4 once any number ≥ 1000). x86_64 is the canonical numbering; the
  aarch64 dispatch routes its own number to the **same** file (one logical
  syscall, one file, both arches).
- `<name>` = the Linux syscall name, lowercase (`read`, `openat`, `clock_nanosleep`).
- Examples: `000_read.rs`, `001_write.rs`, `257_openat.rs`, `101_ptrace.rs`.

Rules:
- A syscall currently sharing a grouped file (`fs.rs`, `net.rs`, …) **MUST be
  moved** into its own `<NNN>_<name>.rs`. Grouped multi-syscall files are abolished.
- A syscall with no file yet (missing/`ENOSYS`/new) **gets a new** `<NNN>_<name>.rs`.
- The file holds exactly that one syscall's handler `pub fn sys_<name>(...)` plus
  its own imports / `SAFETY` / doc-comments — nothing else.
- The module root (`lib.rs`/`mod.rs`) becomes pure wiring: `mod NNN_<name>;` per
file plus dispatch-table registration. No syscall bodies in root.
- The 17 OBSOLETE numbers (`15` legend) need no file — they register `sys_enosys`.
- This makes coverage auditing trivial: one file per implemented number; a
  missing `<NNN>_<name>.rs` = an unimplemented syscall.

If the flat directory grows unwieldy, files may be grouped into range subdirs
(`000_099/000_read.rs`, …) — the **filename** rule (`<NNN>_<name>.rs`, one
syscall) is invariant; only parent dir may change. Migration is per-syscall and
ledger-driven.

## 1

| Role | Concern | Location |
|---|---|---|
| ABI crate | ABI infrastructure | `crates/kernel/syscall` |
| Work fns | Subsystem work | `crates/kernel/<sub>` |
| Shim | ABI shim | `crates/kernel/syscalls/src/` |

Strict dep direction: the shim imports both the work fns and the ABI crate; the work fns import neither. The work fns never import the ABI crate or the shim. The ABI crate never imports the work fns or the shim.

## 2

Foundational ABI types. No upward deps.

Owns:
- `SyscallArgs` — 6×u64 register snapshot per `15§1.3`.
- `Errno` enum — Linux-numbered ABI encoding per `15§7`.
- `nrs::*` — Linux x86_64 NR constants per `15§2`.
- `userptr::*` — `UserPtr<T>` / `UserSlice<T>` range + alignment validators per `15§1.4`.

Forbids:
- Importing any subsystem crate.
- Importing `sched`, `vfs`, `vmm`, `net`, `fs`, etc.

Allowed deps: `hal`, `klog` only.

Live dispatch belongs only to `crates/kernel/syscalls/src/dispatch/core.rs` (§5).

## 3

Each subsystem crate exposes **typed** functions doing the actual work.

Contract for every work fn:
- Takes concrete typed args (`&Arc<File>`, `&[u8]`, struct refs). **Never** `&SyscallArgs`.
- Returns typed `Result<T,<Subsystem>Error>`. **Never** `i64` or ABI `Errno`.
- Does **not** call `sched::current()`. Caller passes whatever task state is needed as a typed arg (e.g., `cur: &Arc<Task>`, `creds: &Creds`).
- Does **not** call `userptr::validate_*`. User-pointer validation is the shim's job; the work layer takes already-validated `&[u8]` slices.
- Hosted-testable: builds on host with mocked subsystem state. No `#![cfg(target_os = "oxide-kernel")]` at module level.

Examples:
```rust
// vfs::file
pub fn read(file: &Arc<File>, buf: &mut [u8]) -> VfsResult<usize>;
pub fn lseek(file: &Arc<File>, off: i64, whence: Whence) -> VfsResult<u64>;

// vmm::mmap
pub fn mmap(as_: &AddressSpace, addr: u64, len: usize, prot: VmaProt, flags: MapFlags,
            file: Option<&Arc<File>>, offset: u64) -> MmResult<u64>;

// sched::fork
pub fn clone(parent: &Arc<Task>, flags: CloneFlags, stack: u64, tls: u64,
             ptid: Option<u64>, ctid: Option<u64>) -> SchedResult<Tid>;

// net::socket
pub fn sendto(sock: &Arc<Socket>, buf: &[u8], dest: SockAddr) -> NetResult<usize>;
```

Allowed deps within the work layer: another work-layer subsystem if there's no cycle. E.g., `net::socket::sendto` may call `vfs` if vfs doesn't depend on net.

## 4

Per-syscall shim functions. One per `sys_X` slot in the dispatch table.

Contract for every ABI shim:
- Signature: `pub fn sys_X(args: &SyscallArgs) -> i64`.
- Body: exactly five phases, in order.

Phase | Action
---|---
parse | extract typed args from `args.a0..a5`
validate | call `userptr::validate_*` for any user buffer
fetch | look up `sched::current()`, pull creds/fd_table/mm as needed
call | invoke one work fn
encode | map subsystem result/error → Linux `Errno`/`i64` per `15§7`

Target body size: 10–30 LOC. Anything longer means work logic leaked into the shim — push it down to the work layer.

Example:
```rust
pub fn sys_read(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2 as usize;
    let cur = match sched::current() { Some(c) => c, None => return -EFAULT_I64 };
    let file = match cur.fd_table.get(fd) { Some(f) => f, None => return -EBADF_I64 };
    if let Err(rv) = userptr::validate_user_buf_writable(buf, cnt as u64, 1) { return rv; }
    // SAFETY: validate_user_buf_writable checked range and write VMA per `15§1.4`.
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, cnt) };
    match vfs::file::read(&file, slice) {
        Ok(n) => n as i64,
        Err(e) => -(map_vfs_errno(e).as_i32() as i64),
    }
}
```

Allowed deps in `crates/kernel/syscalls/src/`:
- `syscall::*` for `SyscallArgs`, `Errno`, `userptr`, `nrs`
- `sched::current()` and `sched::live::*` for task state
- Every work crate
- `hal` for user/kernel boundary

## 4.1

The 10–30 LOC target is a **hard rule**, not a guideline: a shim parses,
validates, fetches task state, calls **one** work fn, encodes. Any
policy, allocation, fs/mm/ipc/net mutation, loop over work, or "special case"
in a shim = a layering violation. Each syscall's work lives in **exactly one**
work-layer fn — never duplicated in the shim, never split across shim + crate.

**Current violations (must-fix):** work has leaked into
the shim and must move down to a work-layer crate fn —
- `read`/`write` core path in the handler crate belongs in `vfs`.
- `brk` carries cgroup `memory.max` charge/uncharge **policy** in the shim → `mm`/`cgroup`.
- `pipe` creates the pipe inode + writes the fd pair to user memory from the shim → `fs`.
- `getpid` PID-namespace visibility logic in the shim → `sched`.
- `socket`/`sendto`/`recvfrom`/`sendmsg`/`recvmsg` special-case netlink/AF_PACKET/cmsg in the shim → `net`.
Closing these is part of making each `IMPL` syscall correct, not a separate effort.

Scheduler shims follow the same hard boundary. They decode/probe arguments,
resolve the target and credentials, call one typed scheduler operation, and
encode its result. Nice conversion, policy/admission checks that depend on live
scheduler state, runqueue lookup, class/priority/load derivation, PI interaction,
affinity composition, and mutation belong to `crates/kernel/sched`. Native
process/thread information shims follow the same rule and cannot keep a Windows
priority or affinity result outside scheduler-owned configuration/state.

## 5

**Single source of truth: the live dispatcher rooted at
`crates/kernel/syscalls/src/dispatch/core.rs`** plus its route modules. It routes
Linux numbers from `nrs::NR_*` and the separate native selector namespace. Size
tracks the highest registered Linux number and is never a stale hardcoded bound.

Population: the kernel installs a default table where every slot is
`sys_enosys`, then registers ABI shims by NR. OBSOLETE numbers (`15` legend)
register a deliberate `sys_enosys` to match Linux; every other number registers
a real shim.

The foundational `crates/kernel/syscall` crate owns ABI types and registry data,
not a second live dispatcher. New routes go only through the handler crate's
dispatch root.

## 6

Forbidden:
- `vfs::syscalls::*`
- `sched::syscalls::*`
- `net::syscalls::*`

Reason: work-layer subsystems are pure work-fn modules. Adding a `syscalls/` submodule that takes `&SyscallArgs` violates the "subsystem doesn't know ABI" contract. Shims belong in the shim.

Subsystem `sched::syscalls::*` modules are forbidden. Scheduler work functions
live under `sched`; matching ABI handlers live in `crates/kernel/syscalls/src/`.

## 7

For `sys_X` touching multiple subsystems, the shim orchestrates. Example `sys_execve`:

```rust
pub fn sys_execve(args: &SyscallArgs) -> i64 {
    // parse + validate
    let path = ...;
    let argv = ...;
    let envp = ...;
    let cur  = sched::current()?;
    // call into multiple work-layer fns
    let image = exec::load_elf(path)?;
    let new_as = vmm::address_space::new_for_exec(&image)?;
    let stack = exec::stack::build(&image, argv, envp)?;
    sched::live::exec_replace(&cur, new_as, image.entry, stack)?;
    0
}
```

ABI shim is allowed to call multiple work-layer fns and weave their results. No work-layer fn calls another subsystem's syscalls; it only calls other subsystems' typed work fns.

## 8

| Pattern | Why |
|---|---|
| the work layer fn takes `&SyscallArgs` | ABI leaked into subsystem |
| work fn returns `i64` or `Errno` | ABI leaked into subsystem |
| the work layer fn calls `sched::current()` | Implicit task dep; pass it in |
| the work layer fn calls `userptr::validate_*` | User-pointer concern is ABI-level |
| ABI shim body > 50 LOC | Work logic leaked from the work layer |
| ABI shim does any I/O directly | Should call work fn |
| `<subsystem>::syscalls::*` namespace | Mixes ABI surface into pure work |
| `crate::syscall_glue_*` legacy name | Replaced by handler in `crates/kernel/syscalls/src/` |

## 9

Work fns: hosted unit tests. Mock subsystem state, call typed args, assert typed
subsystem result. No `SyscallArgs`, `Errno`, or `current()`.

ABI shims: thin enough that hosted unit tests aren't required. CI exercises them via the integration smokes (per `42`) that go through the real dispatch table.

Dispatch table: hosted test under `crates/kernel/syscalls/src/dispatch/` verifies
every live slot is occupied and only `15` OBSOLETE slots route to `sys_enosys`.

## 10

Single-syscall granularity. Per syscall:

1. Identify work logic inside `crates/kernel/syscalls/src/<NNN>_<name>.rs` or a
   legacy grouped handler.
2. Extract that body to a typed `pub fn X(...)` in the owning subsystem crate. Hosted-test it.
3. Replace `kernel_sys_X` with a ABI shim per `§4`: parse → validate → fetch → call → encode.
4. Rename `kernel_sys_X` → `sys_X` (drop legacy prefix).
5. Dispatch routing remains unchanged; only the handler body changes.

Each migration is its own PR. Order by complexity:
- vfs reads/writes/opens/closes (mostly straightforward fd_table → File ops)
- mmap/mprotect/munmap (single subsystem)
- net socket family (single subsystem)
- cred/prctl/rseq (sched single subsystem)
- clone/fork/execve (cross-subsystem orchestration; harder)

## 11

Work fn: `<subsystem>::<module>::<verb>` — e.g., `vfs::file::read`,
`vmm::mmap::mmap`, `sched::fork::clone`. No `sys_` prefix. Returns typed
subsystem result.

ABI shim: `syscalls::<NNN>_<name>::sys_<name>` — name matches Linux. Returns `i64`.

Legacy `kernel_sys_*` names are deprecated; rename on migration.

## 12

Existing inline work is migration debt, not authorization for new code. A change
touching a legacy handler must not add policy or field mutation there. If the
requested behavior needs such work, the same change first creates or extends the
typed owner operation and leaves the handler as parse/validate/fetch/call/encode.
Scheduler handlers have no exception to this rule.

## 13

A ABI shim file passes review only if every `sys_X` it contains conforms to `§4`:
- < 50 LOC body
- Calls exactly one (or for orchestration, a small handful of) work fn(s)
- No work logic inline

Spec-lint enforcement scans `crates/kernel/syscalls/src/**/*.rs` for
`pub fn sys_*` and rejects handler bodies over 50 lines or inline work logic.
