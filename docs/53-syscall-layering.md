# 53 Syscall layering

DRAFT (living). Dep: `02`,`08`,`13`,`15`,`52`.

Architecture for how syscall code is organized across crates. `15` defines the ABI; this doc defines where each piece of an `sys_X` implementation lives.

## 1 Three tiers

| Tier | Concern | Location |
|---|---|---|
| 1 | ABI infrastructure | `crates/kernel/syscall` |
| 2 | Subsystem work | `crates/kernel/<sub>` |
| 3 | ABI shim | `kernel/src/syscalls/` |

Strict downward dep direction: Tier 3 → Tier 2 → Tier 1. Tier 2 never imports Tier 1 or Tier 3. Tier 1 never imports Tier 2 or Tier 3.

## 2 Tier 1 — `syscall` crate

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

## 3 Tier 2 — subsystem work

Each subsystem crate exposes **typed** functions doing the actual work.

Contract for every Tier-2 work fn:
- Takes concrete typed args (`&Arc<File>`, `&[u8]`, struct refs). **Never** `&SyscallArgs`.
- Returns `KResult<T>` with typed `T`. **Never** `i64`.
- Does **not** call `sched::current()`. Caller passes whatever task state is needed as a typed arg (e.g., `cur: &Arc<Task>`, `creds: &Creds`).
- Does **not** call `userptr::validate_*`. User-pointer validation is Tier 3's job; Tier 2 takes already-validated `&[u8]` slices.
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

Allowed deps within Tier 2: another Tier-2 subsystem if there's no cycle. E.g., `net::socket::sendto` may call `vfs` if vfs doesn't depend on net.

## 4 Tier 3 — ABI shim

Per-syscall shim functions. One per `sys_X` slot in the dispatch table.

Contract for every Tier-3 shim:
- Signature: `pub fn sys_X(args: &SyscallArgs) -> i64`.
- Body: exactly four phases, in order.

Phase | Action
---|---
parse | extract typed args from `args.a0..a5`
validate | call `userptr::validate_*` for any user buffer
fetch | look up `sched::current()`, pull creds/fd_table/mm as needed
call | invoke one Tier-2 work fn
encode | map `KResult<T>` → `i64` per `15§7`

Target body size: 10–30 LOC. Anything longer means work logic leaked into the shim — push it down to Tier 2.

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
- Every Tier-2 work crate
- `hal` for user/kernel boundary

## 5 Dispatch table

Lives in `crates/kernel/syscall/dispatch.rs` per `15§1.3`. Static `[SyscallFn; 462]` array indexed by `nrs::NR_*`.

Population: kernel binary at boot installs a default table where every slot points to `sys_enosys`, then registers Tier-3 shims by NR. Per `15§4` table-build.

Alternative: const-fn table assembly. Tier-3 shims live in `kernel/src/syscalls/<sub>.rs`; the dispatch table imports each `sys_X` directly and lists them by NR.

## 6 No `syscalls/` submodule inside subsystem crates

Forbidden:
- `vfs::syscalls::*`
- `sched::syscalls::*`
- `net::syscalls::*`

Reason: Tier-2 subsystems are pure work-fn modules. Adding a `syscalls/` submodule that takes `&SyscallArgs` violates the "subsystem doesn't know ABI" contract. Shims belong in Tier 3.

R58's `sched::syscalls::*` was incorrect under this spec. R60 reworks it: each file moves up one level (`sched::syscalls::cred` → `sched::cred`), drops the `SyscallArgs` signature, exposes typed work fns. A matching Tier-3 shim lives in `kernel/src/syscalls/cred.rs`.

## 7 Cross-subsystem syscalls

For `sys_X` touching multiple subsystems, Tier 3 orchestrates. Example `sys_execve`:

```rust
pub fn sys_execve(args: &SyscallArgs) -> i64 {
    // parse + validate
    let path = ...;
    let argv = ...;
    let envp = ...;
    let cur  = sched::current()?;
    // call into multiple Tier-2 fns
    let image = exec::load_elf(path)?;
    let new_as = vmm::address_space::new_for_exec(&image)?;
    let stack = exec::stack::build(&image, argv, envp)?;
    sched::live::exec_replace(&cur, new_as, image.entry, stack)?;
    0
}
```

Tier 3 shim is allowed to call multiple Tier-2 fns and weave their results. No Tier-2 fn calls another subsystem's syscalls; it only calls other subsystems' typed work fns.

## 8 Forbidden patterns

| Pattern | Why |
|---|---|
| Tier 2 fn takes `&SyscallArgs` | ABI leaked into subsystem |
| Tier 2 fn returns `i64` (errno) | ABI leaked into subsystem |
| Tier 2 fn calls `sched::current()` | Implicit task dep; pass it in |
| Tier 2 fn calls `userptr::validate_*` | User-pointer concern is ABI-level |
| Tier 3 shim body > 50 LOC | Work logic leaked from Tier 2 |
| Tier 3 shim does any I/O directly | Should call Tier-2 work fn |
| `<subsystem>::syscalls::*` namespace | Mixes ABI surface into pure work |
| `crate::syscall_glue_*` legacy name | Replaced by `crate::syscalls::*` in `kernel/src/` per R30 |

## 9 Test contract

Tier 2 work fns: hosted unit tests. Mock the subsystem state, call the fn with typed args, assert `KResult<T>`. No `SyscallArgs`, no `current()`. Lives next to the fn in the subsystem crate.

Tier 3 shims: thin enough that hosted unit tests aren't required. CI exercises them via the integration smokes (per `42`) that go through the real dispatch table.

Dispatch table: hosted test in `crates/kernel/syscall/src/tests.rs` verifies every slot is occupied (no `sys_enosys` slots that should be handled).

## 10 Migration ladder

Single-syscall granularity. Per syscall:

1. Identify the work logic inside `kernel/src/syscalls/<sub>.rs::kernel_sys_X`.
2. Extract that body to a typed `pub fn X(...)` in the owning subsystem crate. Hosted-test it.
3. Replace `kernel_sys_X` with a Tier-3 shim per `§4`: parse → validate → fetch → call → encode.
4. Rename `kernel_sys_X` → `sys_X` (drop legacy prefix).
5. Dispatch table entry stays the same — just a different fn body.

Each migration is its own PR. Order by complexity:
- vfs reads/writes/opens/closes (mostly straightforward fd_table → File ops)
- mmap/mprotect/munmap (single subsystem)
- net socket family (single subsystem)
- cred/prctl/rseq (sched single subsystem)
- clone/fork/execve (cross-subsystem orchestration; harder)

## 11 Naming

Tier 2 work fn: `<subsystem>::<module>::<verb>` — e.g., `vfs::file::read`, `vmm::mmap::mmap`, `sched::fork::clone`. No `sys_` prefix. Returns `KResult<T>` with typed `T`.

Tier 3 shim: `kernel::syscalls::<sub>::sys_<name>` — name matches Linux. Returns `i64`.

Legacy `kernel_sys_*` names are deprecated; rename on migration.

## 12 What's allowed in Tier 3 today

Until every syscall migrates, Tier-3 files are allowed to:
- Hold the work inline (current state of most handlers)
- Reach into kernel-internal modules (`devfs`, `procfs`, `dev`)

Per-syscall extraction is opportunistic. Don't block a bug fix in `kernel/src/syscalls/X.rs` on first extracting it to Tier 2.

## 13 Test-contract gate

A Tier-3 shim file passes review only if every `sys_X` it contains conforms to `§4`:
- < 50 LOC body
- Calls exactly one (or for orchestration, a small handful of) Tier-2 work fn(s)
- No work logic inline

Spec-lint enforcement: future `xtask spec-lint` extension scans `kernel/src/syscalls/**/*.rs` for `pub fn sys_*` and warns when body LOC exceeds 50.
