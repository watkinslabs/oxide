# 27 Security

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`11`,`13`,`16`,`18`,`26`,`38`. Provides:every privilege check.

## 1 Purpose

Capabilities (Linux v3, 64-bit), seccomp (strict + filter), Landlock (filesystem sandbox), KASLR/KPTI/SMEP/SMAP/PAN/PXN/CET/BTI baseline, signature trust root, taint flags, sysctl tree.

## 2 Invariants (frozen)

1. Every privileged op gates on a capability check evaluated against the current task's effective set within its user-ns.
2. SMEP/SMAP (x86) and PAN/PXN (arm) on at all times in kernel mode (per `03§8`).
3. W^X universal (kernel + user); enforced by VMM at every map.
4. Stack canaries on every kernel non-leaf function; `__stack_chk_fail` halts.
5. Seccomp filter, once installed, cannot be removed; `NoNewPrivs` set on filter install (irreversible).
6. Trusted module signing root: built into kernel image as PEM cert; verified at compile.
7. Taint flags (bitmask) recorded on first untrusted action; appears in `/proc/sys/kernel/tainted` and panic output.

## 3 Public ifc

```rust
pub fn cap_check(cap:u8) -> KR<()>;                // EPERM if missing
pub fn cap_check_in_userns(cap:u8, userns:&UserNs) -> KR<()>;

pub fn seccomp_set_strict() -> KR<()>;             // only read,write,exit,sigreturn allowed
pub fn seccomp_set_filter(prog:&BpfProg) -> KR<()>;// per phase 23 once BPF lands

pub fn landlock_create_ruleset(attr:&LandlockRulesetAttr) -> KR<RawFd>;
pub fn landlock_add_rule(ruleset:RawFd, kind:u32, attr:&LandlockAttr, flags:u32) -> KR<()>;
pub fn landlock_restrict_self(ruleset:RawFd, flags:u32) -> KR<()>;

pub fn taint(flag:TaintFlag, msg:&'static str);
```

## 4 Capabilities

`Caps` per `01§9`. Per-task: effective, permitted, inheritable, bounding, ambient.

Transition rules: `execve` of file with file caps + setuid bits → recompute per Linux capability(7) rules. NoNewPrivs blocks privilege gain.

User-ns scoping: a cap authorizes an operation on `target_user_ns` only when the bit is set AND `target_user_ns` is the caller's user-ns or a descendant of it (a task in the initial ns sees every ns as a descendant). Each user-ns records its parent at creation; the check walks that chain (`26§3.6`). Unscoped `has_cap` at a privileged site is a bug: a task that unshared `CLONE_NEWUSER` holds full caps in its own ns and must not reach a sibling ns's resources.

## 5 Seccomp

### 5.1 Strict mode
Only `read`, `write`, `_exit`, `rt_sigreturn` allowed; everything else → SIGKILL. Useful for sandboxed compute.

### 5.2 Filter mode
BPF prog evaluated on every syscall; returns action (`ALLOW`,`KILL`,`KILL_PROCESS`,`TRAP`,`ERRNO`,`USER_NOTIF`,`LOG`,`TRACE`).

Now: returns ENOSYS for filter mode (BPF tracked as phase 23). Strict mode works.
Phase 23: ship the BPF subset needed for seccomp filters.

## 6 Landlock

Landlock target: ABI 10 (Linux 7.2 UAPI).

The target is independent of the compatibility release returned by `uname(2)`.
Landlock has its own runtime negotiation through
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`; changing a
UTS release does not raise or lower this contract. ABI 10 was re-verified
against Linux 7.2 on 2026-08-05.

`landlock::uapi::TARGET_ABI_VERSION` is the code source of truth and
`ABI_VERSION` is the value returned to userspace. The ABI test reads the exact
target line above, so changing either side alone fails. An ABI number is a
cumulative security claim: it may advance only when every rung through that
number is implemented and its behavioural tests pass. Implementing a later
rung never permits skipping an earlier mismatch.

| ABI | Cumulative addition | Oxide goal |
|---:|---|---|
| 1 | filesystem hierarchy rules and base filesystem rights | enforced |
| 2 | `LANDLOCK_ACCESS_FS_REFER` | enforced |
| 3 | `LANDLOCK_ACCESS_FS_TRUNCATE` | enforced |
| 4 | TCP bind/connect port rights | enforced |
| 5 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` | enforced |
| 6 | abstract-UNIX-socket and signal scopes | enforced |
| 7 | denial-logging controls | accepted; audit-disabled behaviour is intentional until an audit subsystem exists |
| 8 | `LANDLOCK_RESTRICT_SELF_TSYNC` | enforced; pseudo-signal task work, repeated clone discovery, and two commit barriers make the live thread group all-or-nothing |
| 9 | pathname UNIX-socket resolution | enforced |
| 10 | UDP port rights, quiet rules, and quiet masks | enforced |

TSYNC and `execve(2)` share the process's one `exec_update_lock`, matching
Linux. A concurrent writer restarts before committing anything. Every sibling
performs its own credential update in the common return-to-user work loop;
foreign CPUs never overwrite a running task's security state. Discovery repeats
until a full scan finds no new child, then all parked siblings cross the commit
barrier together and the caller commits last.

Errata are tracked separately from the ABI number.
Oxide advertises errata 1 (TCP-only port rights), 2 (same-process signal scope), and 3 (disconnected directory hierarchy handling).
Refer checks combine rights from a hierarchy disconnected by a move outside a
bind mount with rights from the saved bind-mount root and its mount-point
ancestry, so neither half can widen `LANDLOCK_ACCESS_FS_REFER` policy.

Rulesets are inherited and cannot be loosened. Filesystem, network, and scope
decisions all consume one immutable per-task domain; no second policy registry
or release-derived feature table is permitted.

## 7 Sigverify (modules + kexec)

Signature trailer: PKCS#7 / detached RSA-PSS-SHA256.
Trust root: one or more X.509 certs embedded in kernel image at build (env var `OXIDE_TRUSTED_KEYS`).
Verification: `sig.verify(rest_of_file, trust_root)`.

If `module.sig_enforce=1` (default): unsigned module → ENOEXEC.
If `module.sig_enforce=0`: load + set `T_UNSIGNED` taint.

## 8 Taint flags (32-bit bitmap)

| Bit | Name | Set when |
|---|---|---|
| 0 | T_PROPRIETARY | proprietary module loaded (we don't have any; reserved) |
| 1 | T_FORCE_LOAD | module force-loaded against version |
| 2 | T_UNSIGNED | unsigned module loaded |
| 3 | T_OVERRIDDEN | sysctl override of safety knob |
| 4 | T_HW_INCONSISTENT | hardware inconsistency detected (TSC, ACPI, ...) |
| 5 | T_DIE | a previous panic/oops occurred |
| 6 | T_DEBUG_LOAD | a debug-only feature enabled |
| ... | reserved | |

Reset only by reboot.

## 9 KASLR

Kernel image base randomized at boot (8-bit entropy, page-aligned within the higher-half image area). Direct map base randomized (16-bit). vDSO mapped at randomized user va per process.

Now: kernel base fixed (no relocation logic yet). Tracked as later phase. Spec'd here so layout doesn't break later.

## 10 KPTI

Per `20§6`,`21§6`. On by default. `pti=off` cmdline disables (sets `T_OVERRIDDEN`).

## 11 W^X

Kernel: `.text` R+X, `.rodata` R, `.data`/`.bss` R+W. Trampoline-only writable text rejected at link time (linker script). Modules: same.
User: `mmap` rejects PROT_WRITE+PROT_EXEC; `mprotect` likewise. JITs use dual-mapping.

## 12 Stack canaries

All kernel fns built with `+stack-protector=strong`. `__stack_chk_guard` per-CPU randomized at boot. `__stack_chk_fail` calls `panic_static("stack smash detected", ...)`.

## 13 sysctl

A sparse tree of `/proc/sys/...` knobs. Each registered via `sysctl_register(path, kind, getter, setter)`. Kinds: bool, i32, u64, string, ipset.

Current subset:
- `kernel.{tainted,modules_disabled,unprivileged_userns_clone,kexec_load_disabled,perf_event_paranoid,kptr_restrict,randomize_va_space,sysrq,printk}`
- `vm.{overcommit_memory,overcommit_ratio,oom_kill_allocating_task,swappiness}`
- `fs.{file-max,nr_open,protected_symlinks,protected_hardlinks,protected_fifos,protected_regular,suid_dumpable}`
- `net.core.{rmem_max,wmem_max,somaxconn}`,`net.ipv4.{tcp_*,ip_forward,...}`,`net.ipv6.*`

Setting many of these requires CAP_SYS_ADMIN and may set `T_OVERRIDDEN`.

## 14 Concurrency

- Capability check: per-task creds `Arc<Credentials>`; immutable; `setuid`/`capset` rebuild and replace.
- Seccomp filter chain: per-task `Arc<FilterChain>`; immutable post-install.
- Landlock ruleset: per-task `Arc<LandlockSet>`.
- Trust root: static, no lock.
- Taint: AtomicU32, Relaxed.

## 14a Crypto implementation

Algos allowed/denied per `03§8`. This section spec'd impl side.

### 14a.1 Crate selection (no scratch crypto)

| Algo | Crate | Why |
|---|---|---|
| ChaCha20-Poly1305 | `chacha20poly1305` (RustCrypto) | audited; no_std; constant-time |
| AES-256-GCM(-SIV) | `aes-gcm`, `aes-gcm-siv` (RustCrypto) | same; AES-NI accel via `aes` crate when avail |
| SHA-256/512/3 | `sha2`,`sha3` (RustCrypto) | same |
| BLAKE3 | `blake3` | own crate; SIMD-accel; fastest |
| HMAC | `hmac` | RustCrypto |
| HKDF | `hkdf` | RustCrypto |
| Argon2id | `argon2` | RustCrypto; password hashing only |
| X25519 | `x25519-dalek` | dalek-cryptography |
| Ed25519 | `ed25519-dalek` | dalek; sig verify hot path |
| P-256 | `p256` (RustCrypto) | for cert chains |
| Kyber/ML-KEM | `pqcrypto-kyber` or `ml-kem` | PQ hybrid; vendored when stable |
| TLS 1.3 | `rustls` (kernel-fork) | kTLS data path; rustls handshake in userspace, kernel for record-layer |

Constraint: every crate `no_std`-able. Vendored at workspace root with version pin.

### 14a.2 RNG sourcing

Boot: gather entropy from RDRAND/RDSEED (x86) / RNDR-RNDRRS (arm FEAT_RNG) / virtio-rng (always); EFI RNG protocol if present; jitterentropy (timing jitter) as fallback. Mix via SHAKE-256.

Steady state: `getrandom()` (syscall 318 in `15§2`) reads from a per-system DRBG (HMAC-SHA-256 DRBG, NIST SP 800-90A). Reseeded every 2^16 bytes from raw RDRAND/RDSEED/virtio-rng pool.

Per-CPU rapid RNG (for non-cryptographic use): xoshiro256++ seeded from main DRBG; not exposed to userspace.

### 14a.3 Key management

- Module-signing trust root: PEM cert(s) embedded at kernel build (env `OXIDE_TRUSTED_KEYS`); never modifiable at runtime.
- TLS handshake: in userspace; kernel sees only symmetric keys via `kTLS` setsockopt.
- Disk encryption (dm-crypt, later phase): keys held in kernel keyring (`add_key`/`request_key`, phase 24); never in pageable memory.
- Memfd_secret pages: phys never in kernel direct map per `03§4`.

### 14a.4 Constant-time invariants

All cmp/key-ops on secret material via `subtle::ConstantTimeEq`. Memcmp-on-secrets is a build-fail (clippy lint `oxide_constant_time`).

### 14a.5 Forbidden patterns

- `Vec<u8>` holding key material outside `Zeroizing<Vec<u8>>` from `zeroize`.
- Allocator-default randomization for crypto buffers (use `getrandom`).
- TLS 1.0/1.1/1.2 acceptance anywhere in userspace ABI we expose; rustls-fork rejects pre-1.3 client/server hellos.
- MD5/SHA-1 in any path including Git-style content addressing — use SHA-256 or BLAKE3.

## 15 Perf budget

| Op | p99 cy |
|---|---|
| `cap_check` (hit, in current ns) | ≤ 30 |
| `cap_check_in_userns` (1-deep) | ≤ 80 |
| Seccomp strict path-check (per syscall) | ≤ 20 |
| Seccomp filter eval (BPF, phase 23) | ≤ 200 |
| Landlock check on `openat` | ≤ 300 |

## 16 Test contract (frozen)

- Cap check: drop CAP_SYS_ADMIN, attempt mount; EPERM.
- Seccomp strict: program triggers `mmap`; receives SIGSYS/SIGKILL.
- Landlock: ruleset blocks `/etc`; openat returns EACCES.
- W^X: `mmap(PROT_WRITE|PROT_EXEC)` returns EINVAL.
- Stack smash: deliberately overflow buffer in test mode; panic with canary message.
- Taint: load unsigned module with sig_enforce=0; `T_UNSIGNED` set; `/proc/sys/kernel/tainted` reflects.
- KASLR (once enabled): kernel base differs across boots.
- Coverage ≥90% on `crates/security/`.

## 17 Failure modes

- Missing cap: `EPERM`, never panic.
- Seccomp violation: SIGSYS or KILL per filter action.
- Landlock violation: `EACCES`.
- Stack canary fail: panic.

## 18 Debug

`debug-security`: log every cap_check denial, seccomp action, landlock denial.

## 19 Cross-spec

`13` (CAP_SYS_NICE for RT scheduling), `18` (sig verify, taint), `26` (caps in user-ns), `15` (capset, seccomp, landlock_*), `11` (W^X enforced at mmap).
