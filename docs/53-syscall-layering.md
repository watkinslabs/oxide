# 53 Syscall layering

DRAFT (living). Dep: `02`,`08`,`13`,`15`,`52`.

Architecture for how syscall code is organized across crates. `15` defines the ABI; this doc defines where each piece of an `sys_X` implementation lives.

## 0 One syscall = one file (HARD RULE)

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
  file + the dispatch-table registration. No syscall bodies in the root.
- The 17 OBSOLETE numbers (`15` legend) need no file — they register `sys_enosys`.
- This makes coverage auditing trivial: one file per implemented number; a
  missing `<NNN>_<name>.rs` = an unimplemented syscall.

If the flat directory grows unwieldy, files may be grouped into range subdirs
(`000_099/000_read.rs`, …) — the **filename** rule (`<NNN>_<name>.rs`, one
syscall) is invariant; only the parent dir may change. Migration is per-syscall,
folded into the audit-driven coverage work (`syscal_anal.md`).

## 1 Three layers

| Role | Concern | Location |
|---|---|---|
| ABI crate | ABI infrastructure | `crates/kernel/syscall` |
| Work fns | Subsystem work | `crates/kernel/<sub>` |
| Shim | ABI shim | `kernel/src/syscalls/` |

Strict dep direction: the shim imports both the work fns and the ABI crate; the work fns import neither. The work fns never import the ABI crate or the shim. The ABI crate never imports the work fns or the shim.

## 2 ABI crate — `syscall`

Foundational ABI types. No upward deps.

Owns:
- `SyscallArgs` — 6×u64 register snapshot per `15§1.3`.
- `Errno` enum — Linux-numbered, the universal `KResult<T>` error per `15§7`.
- `dispatch(nr, args) -> i64` — table-driven dispatch per `15§1.3`.
- `nrs::*` — Linux x86_64 NR constants per `15§2`.
- `userptr::*` — `UserPtr<T>` / `UserSlice<T>` range + alignment validators per `15§1.4`.

Forbids:
- Importing any subsystem crate.
- Importing `sched`, `vfs`, `vmm`, `net`, `fs`, etc.

Allowed deps: `hal`, `klog` only.

Reason: `hal-x86_64::pt_regs::syscall_entry` calls `syscall::dispatch`, so `syscall` sits below `hal` in the dep graph. Any upward dep cycles through `hal`.

## 3 Work fns — subsystem work

Each subsystem crate exposes **typed** functions doing the actual work.

Contract for every work fn:
- Takes concrete typed args (`&Arc<File>`, `&[u8]`, struct refs). **Never** `&SyscallArgs`.
- Returns `KResult<T>` with typed `T`. **Never** `i64`.
- Does **not** call `sched::current()`. Caller passes whatever task state is needed as a typed arg (e.g., `cur: &Arc<Task>`, `creds: &Creds`).
- Does **not** call `userptr::validate_*`. User-pointer validation is the shim's job; the work layer takes already-validated `&[u8]` slices.
- Hosted-testable: builds on host with mocked subsystem state. No `#![cfg(target_os = "oxide-kernel")]` at module level.

Examples:
```rust
// vfs::file
pub fn read(file: &Arc<File>, buf: &mut [u8]) -> KResult<usize>;
pub fn lseek(file: &Arc<File>, off: i64, whence: Whence) -> KResult<u64>;

// vmm::mmap
pub fn mmap(as_: &AddressSpace, addr: u64, len: usize, prot: VmaProt, flags: MapFlags,
            file: Option<&Arc<File>>, offset: u64) -> KResult<u64>;

// sched::fork
pub fn clone(parent: &Arc<Task>, flags: CloneFlags, stack: u64, tls: u64,
             ptid: Option<u64>, ctid: Option<u64>) -> KResult<Tid>;

// net::socket
pub fn sendto(sock: &Arc<Socket>, buf: &[u8], dest: SockAddr) -> KResult<usize>;
```

Allowed deps within the work layer: another work-layer subsystem if there's no cycle. E.g., `net::socket::sendto` may call `vfs` if vfs doesn't depend on net.

## 4 Shim — ABI shim

Per-syscall shim functions. One per `sys_X` slot in the dispatch table.

Contract for every ABI shim:
- Signature: `pub fn sys_X(args: &SyscallArgs) -> i64`.
- Body: exactly four phases, in order.

Phase | Action
---|---
parse | extract typed args from `args.a0..a5`
validate | call `userptr::validate_*` for any user buffer
fetch | look up `sched::current()`, pull creds/fd_table/mm as needed
call | invoke one work fn
encode | map `KResult<T>` → `i64` per `15§7`

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
    // SAFETY: validate_user_buf_writable just checked range + write VMA per `15§1.4`.
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, cnt) };
    match vfs::file::read(&file, slice) {
        Ok(n) => n as i64,
        Err(e) => -(e.as_i32() as i64),
    }
}
```

Allowed deps in `kernel/src/syscalls/`:
- `syscall::*` for `SyscallArgs`, `Errno`, `userptr`, `nrs`
- `sched::current()` and `sched::live::*` for task state
- Every work crate
- `hal` for user/kernel boundary

## 4.1 Hard rule: shim holds ZERO work logic

The 10–30 LOC target is a **hard rule**, not a guideline: a shim parses,
validates, fetches task state, calls **one** work fn, encodes. Any
policy, allocation, fs/mm/ipc/net mutation, loop over work, or "special case"
in a shim = a layering violation. Each syscall's work lives in **exactly one**
work-layer fn — never duplicated in the shim, never split across shim + crate.

**Current violations (must-fix; from `syscal_anal.md`):** work has leaked into
the shim and must move down to a work-layer crate fn —
- `read`/`write` core path lives in `kernel/src/syscalls/mod.rs`; belongs in `vfs`.
- `brk` carries cgroup `memory.max` charge/uncharge **policy** in the shim → `mm`/`cgroup`.
- `pipe` creates the pipe inode + writes the fd pair to user memory from the shim → `fs`.
- `getpid` PID-namespace visibility logic in the shim → `sched`.
- `socket`/`sendto`/`recvfrom`/`sendmsg`/`recvmsg` special-case netlink/AF_PACKET/cmsg in the shim → `net`.
Closing these is part of making each `IMPL` syscall correct, not a separate effort.

## 5 Dispatch table

**Single source of truth: the live dispatcher in `kernel/src/syscalls/mod.rs`**
(plus the per-subsystem helper dispatchers it calls). Static `[SyscallFn; N]`
indexed by `nrs::NR_*`, where `N` covers every number in `15§2` (≥ 472 now that
335 and 452–471 are registered — size tracks the highest `NR_*`, never a
hardcoded stale bound).

Population: the kernel installs a default table where every slot is
`sys_enosys`, then registers ABI shims by NR. OBSOLETE numbers (`15` legend)
register a deliberate `sys_enosys` to match Linux; every other number registers
a real shim.

The older `crates/kernel/syscall/src/dispatch.rs` table is **dead** — it
diverged from the live path and makes audits land on the wrong surface. It is
to be deleted so there is one dispatcher. Do not add routes there.

## 6 No `syscalls/` submodule inside subsystem crates

Forbidden:
- `vfs::syscalls::*`
- `sched::syscalls::*`
- `net::syscalls::*`

Reason: work-layer subsystems are pure work-fn modules. Adding a `syscalls/` submodule that takes `&SyscallArgs` violates the "subsystem doesn't know ABI" contract. Shims belong in the shim.

R58's `sched::syscalls::*` was incorrect under this spec. R60 reworks it: each file moves up one level (`sched::syscalls::cred` → `sched::cred`), drops the `SyscallArgs` signature, exposes typed work fns. A matching ABI shim lives in `kernel/src/syscalls/cred.rs`.

## 7 Cross-subsystem syscalls

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

## 8 Forbidden patterns

| Pattern | Why |
|---|---|
| the work layer fn takes `&SyscallArgs` | ABI leaked into subsystem |
| the work layer fn returns `i64` (errno) | ABI leaked into subsystem |
| the work layer fn calls `sched::current()` | Implicit task dep; pass it in |
| the work layer fn calls `userptr::validate_*` | User-pointer concern is ABI-level |
| ABI shim body > 50 LOC | Work logic leaked from the work layer |
| ABI shim does any I/O directly | Should call work fn |
| `<subsystem>::syscalls::*` namespace | Mixes ABI surface into pure work |
| `crate::syscall_glue_*` legacy name | Replaced by `crate::syscalls::*` in `kernel/src/` per R30 |

## 9 Test contract

the work layer work fns: hosted unit tests. Mock the subsystem state, call the fn with typed args, assert `KResult<T>`. No `SyscallArgs`, no `current()`. Lives next to the fn in the subsystem crate.

ABI shims: thin enough that hosted unit tests aren't required. CI exercises them via the integration smokes (per `42`) that go through the real dispatch table.

Dispatch table: hosted test in `crates/kernel/syscall/src/tests.rs` verifies every slot is occupied (no `sys_enosys` slots that should be handled).

## 10 Migration ladder

Single-syscall granularity. Per syscall:

1. Identify the work logic inside `kernel/src/syscalls/<sub>.rs::kernel_sys_X`.
2. Extract that body to a typed `pub fn X(...)` in the owning subsystem crate. Hosted-test it.
3. Replace `kernel_sys_X` with a ABI shim per `§4`: parse → validate → fetch → call → encode.
4. Rename `kernel_sys_X` → `sys_X` (drop legacy prefix).
5. Dispatch table entry stays the same — just a different fn body.

Each migration is its own PR. Order by complexity:
- vfs reads/writes/opens/closes (mostly straightforward fd_table → File ops)
- mmap/mprotect/munmap (single subsystem)
- net socket family (single subsystem)
- cred/prctl/rseq (sched single subsystem)
- clone/fork/execve (cross-subsystem orchestration; harder)

## 11 Naming

the work layer work fn: `<subsystem>::<module>::<verb>` — e.g., `vfs::file::read`, `vmm::mmap::mmap`, `sched::fork::clone`. No `sys_` prefix. Returns `KResult<T>` with typed `T`.

ABI shim: `kernel::syscalls::<sub>::sys_<name>` — name matches Linux. Returns `i64`.

Legacy `kernel_sys_*` names are deprecated; rename on migration.

## 12 What's allowed in the shim today

Until every syscall migrates, shim files are allowed to:
- Hold the work inline (current state of most handlers)
- Reach into kernel-internal modules (`devfs`, `procfs`, `dev`)

Per-syscall extraction is opportunistic. Don't block a bug fix in `kernel/src/syscalls/X.rs` on first extracting it to the work layer.

## 13 Test-contract gate

A ABI shim file passes review only if every `sys_X` it contains conforms to `§4`:
- < 50 LOC body
- Calls exactly one (or for orchestration, a small handful of) work fn(s)
- No work logic inline

Spec-lint enforcement: future `xtask spec-lint` extension scans `kernel/src/syscalls/**/*.rs` for `pub fn sys_*` and warns when body LOC exceeds 50.
