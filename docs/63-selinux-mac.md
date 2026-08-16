# 62 SELinux mandatory access control

DRAFT 2026-08-15. Dep:`01`,`02`,`06`,`08`,`13`,`15`,`16`,`19`,`24`,`25`,`27`,`29`.

## 1 Purpose

Label-based MAC over every kernel object, driven by a binary policy loaded from
userspace. Owns policy parsing, SID allocation, access-decision computation,
the decision cache, `selinuxfs`, and the check points that consult it.

`27` owns capabilities, seccomp, Landlock, sigverify and the hardening flags.
This doc owns the label-based module only. Both are enforced; neither replaces
the other, and a denial from either refuses the operation.

## 2 Invariants (frozen)

| # | Invariant |
|---|---|
| I1 | Deny by default. A decision starts `allowed=0`; only a rule grants. |
| I2 | `auditdeny` starts all-ones and is AND-accumulated. Suppression clears bits; nothing sets them. |
| I3 | Rules are stored against types AND attributes interchangeably. Every lookup expands the type through `type_attr_map`, which always contains the type's own bit. |
| I4 | A context the loaded policy cannot interpret is RETAINED verbatim, never discarded. A reload that drops a type must not mass-relabel the objects that carried it. |
| I5 | A cached decision computed against a superseded policy is never used and never inserted. Policy load and boolean commit both bump the sequence number. |
| I6 | MLS dominance requires BOTH a sensitivity at least as high AND a category superset. |
| I7 | Permissive is per-domain, keyed on the SOURCE type. |
| I8 | Before the first policy load there is no policy: every check is allowed. This is the bootstrap window, not a permissive mode. |
| I9 | A malformed policy image is refused whole. No partial load is ever consultable. |
| I10 | The decision engine reads no task state, touches no filesystem, and logs nothing. Callers supply SIDs and act on the verdict. |

## 3 Layering

| Layer | Crate | Gated |
|---|---|---|
| Decision engine | `crates/kernel/selinux` | no — pure, hosted-tested |
| Filesystem interface | `crates/kernel/selinuxfs` | mount-time only |
| Check points | existing owners (`vfs`, `fs`, `sched`, `net`, `ipc`, `syscalls`) | per owner |

The engine is a pure library by construction. Every decision — policy parsing,
dominance, cache behaviour, transition computation, constraint evaluation,
context rendering — is a function over values and is tested hosted. A defect
here grants access silently, so `42`'s phantom-test rule applies with no
exceptions: no decision logic may live in a target-gated file.

Landlock (`27§6`) and this module both mediate the same operations. They are
separate decisions combined at the check point by refusing if either refuses;
neither module's state is stored in the other, and there is no shared registry.

## 4 Policy image

Little-endian throughout, no alignment padding. Strings carry a `u32` length
and are not NUL-terminated.

| Section | Order | Version gate |
|---|---|---|
| magic, signature, version, config, `sym_num`, `ocon_num` | 1 | — |
| policy capabilities | 2 | ≥22 |
| permissive types | 3 | ≥23 |
| never-audit types | 4 | ≥35 |
| symbol tables (commons, classes, roles, types, users, bools, levels, cats) | 5 | count per version |
| access-vector table | 6 | format changes at 20 |
| conditional list | 7 | ≥16 |
| role transitions | 8 | class field ≥26 |
| role allows | 9 | — |
| filename transitions | 10 | ≥25, compressed ≥33 |
| object contexts | 11 | count per version |
| genfs contexts | 12 | — |
| range transitions | 13 | ≥19, class field ≥21 |
| type-attribute maps | 14 | ≥20 |

Supported range: 15..=35. `sym_num`/`ocon_num` are cross-checked against the
version; a mismatch is a refusal, because a reader that guesses the section
count reads the next section's bytes as this one's.

Every count in the image is attacker-controlled. Reservation is fallible;
indexing is bounds-checked; a truncated or hostile image yields an error, never
a panic and never an allocation failure.

## 5 Decision path

`compute_av(ssid, tsid, class)`:

1. Initialise: `allowed=0`, `auditallow=0`, `auditdeny=!0`.
2. Resolve both contexts. Unresolvable → deny-all.
3. Permissive and never-audit flags from the SOURCE type. Both set → allow-all.
4. Map the kernel class to the policy class. Unknown → `allow_unknown` decides.
5. For each `(source attribute, target attribute)` pair: unconditional rules,
   then enabled conditional rules, accumulating per I1/I2.
6. Constraints remove permissions. MLS is expressed here; there is no separate
   MLS phase.
7. Role-allow gates process transition and dyntransition.
8. Type bounds mask anything the bound does not also allow.
9. Map the vectors back to kernel bit positions. Never-audit forces both audit
   masks to zero.

`transition_sid` computes user, role, type, then applies a filename transition
over the type, a role transition over the role, and the MLS range last. A
filename match overrides the ordinary result unconditionally.

## 6 Cache

Keyed on the full `(ssid, tsid, class)` triple; a partial-key hit returns
another subject's decision. Sequence-number checked on insert per I5. Reclaim
rotates a bucket hint and evicts in fixed batches once the entry count passes
the threshold. A reclaimed entry is a miss, never a stale hit.

## 7 Labelling

| Behaviour | Source of a label |
|---|---|
| `xattr`, `native` | per-inode `security.selinux`, falling back to the mount default |
| `trans` | transition from the creating task and the mount label |
| `task` | the creating task's label |
| `genfs` | mount label, refined by longest-matching path prefix |
| `none` | unlabelled |
| `mntpoint` | one label for the whole mount, fixed at mount time |

Longest-prefix ordering for genfs is established at load. A shorter prefix
matched first mislabels every object beneath a nested one.

## 8 Filesystem interface

`/sys/fs/selinux`. Userspace reads several of these before it does anything
else, so the set and the formats decide whether a boot works.

| Node | Mode | Contract |
|---|---|---|
| `enforce` | 0644 | read/write decimal flag; write needs `security:setenforce` |
| `load` | 0600 | write whole policy image; needs `security:load_policy` |
| `policyvers` | 0444 | highest version the engine reads |
| `mls` | 0444 | whether the loaded policy carries MLS |
| `status` | 0444 | mappable page: enforcing, policy-load count, deny-unknown |
| `null` | 0666 | character device used to replace revoked descriptors |
| `context` | 0666 | transaction: validate and canonicalise a context |
| `access` | 0666 | transaction: `scon tcon class` → decision fields |
| `create` | 0666 | transaction: `scon tcon class [name]` → new context |
| `relabel` | 0666 | transaction: `scon tcon class` → new context |
| `member` | 0666 | transaction: `scon tcon class` → new context |
| `user` | 0666 | transaction, retained for compatibility |
| `validatetrans` | 0222 | write `old new class task` |
| `checkreqprot` | 0644 | retained, writes are inert |
| `disable` | 0200 | retained, writes are inert |
| `reject_unknown`, `deny_unknown` | 0444 | policy's unknown-class disposition |
| `commit_pending_bools` | 0200 | commit every pending boolean at once |
| `booleans/<name>` | 0644 | read `current pending`; write sets pending only |
| `class/<name>/index`, `class/<name>/perms/<name>` | 0444 | class and permission values |
| `initial_contexts/<name>` | 0444 | context of one initial SID |
| `policy_capabilities/<name>` | 0444 | one file per enabled capability |
| `avc/cache_threshold` | 0644 | cache size bound |
| `avc/hash_stats`, `avc/cache_stats` | 0444 | cache statistics |
| `ss/sidtab_hash_stats` | 0444 | SID table statistics |
| `policy` | 0444 | the loaded image; needs `security:read_policy` |

A boolean write stages a pending value; nothing changes until the commit node
is written. Committing bumps the sequence number, which invalidates the cache.

## 9 Check points

| Group | Where the check belongs |
|---|---|
| task, exec domain transition | `sched`, `exec` |
| inode permission, create, link, rename, xattr | `fs`, `vfs` |
| file open, ioctl, mmap, mprotect, fcntl, receive | `fs`, `syscalls` |
| superblock mount, remount, statfs, umount | `fs` mount paths |
| socket, unix, netlink | `net`, `socket`, `netlink` |
| System V and POSIX IPC | `ipc` |
| capability | the capability owner in `sched` |
| `/proc/<pid>/attr/*` | `procfs` |

Each check point is owned by the subsystem that owns the operation. No check
lives in this module's crate, and this module holds no copy of the state the
owner already has.

`/proc/<pid>/attr/` exposes `current`, `exec`, `fscreate`, `keycreate`,
`sockcreate` and `prev`, each backed by live per-task label state.

## 10 Boot

`selinux=0` disables the module for the boot. `enforcing=` states the initial
mode; its absence leaves the mode to the policy and to userspace. Before the
first load, I8 applies.

## 11 Test contract (frozen)

| # | Contract |
|---|---|
| T1 | The distribution policy image parses, is fully consumed, and its facts are asserted. |
| T2 | Truncation at ≥200 offsets and byte corruption at a spread of offsets yield errors, never panics. |
| T3 | Every type's attribute set contains its own bit (I3). |
| T4 | A rule stored against an attribute grants to a member type and not to a non-member. |
| T5 | Each MLS operator is exercised in both directions, including a case decided by categories alone (I6). |
| T6 | A cache lookup differing in any one key component misses (four cases). |
| T7 | A decision below the sequence watermark is not cached (I5). |
| T8 | Contexts round-trip through render and parse, including two-adjacent and three-adjacent category sets. |
| T9 | A filename transition overrides an ordinary type transition. |
| T10 | Positive control: each of I1, I2, I3, I6 and the permission-bit mapping is reintroduced as a defect and shown to turn the suite red. |

## 12 Cross-spec

`27§4` capabilities, `27§6` Landlock, `16` VFS labelling hooks, `19`
pseudo-filesystem registration, `24` IPC checks, `25` socket checks, `29`
userspace expectations at boot, `53` syscall layering.
