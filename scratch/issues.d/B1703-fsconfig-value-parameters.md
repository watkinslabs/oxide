# B1703 — fsconfig value-carrying parameters

Rows this lane CLOSES (curated `scratch/known_issues.md`):

| Was | Now |
|---|---|
| `fsconfig(2)` `FSCONFIG_SET_FD` / `SET_BINARY` / `SET_PATH` / `SET_PATH_EMPTY` can only ever be rejected (high) | FIXED. `ClassicMountFsContextOps::parse_param` consults the filesystem's table FIRST; `FsParamType::accepts` decides the payload per type. A descriptor-typed key admits a pinned open file, a pathname-typed key admits a pathname. `crates/kernel/vfs/tests/fs_context_value_params.rs` (9 tests). `SET_BINARY` remains refused because no declared type consumes a blob — see the row kept open below. |
| `FSCONFIG_SET_FD` cannot succeed for ANY filesystem; `FsValue::File` has no accepting consumer anywhere in the tree (low) | FIXED. `FsConstructor` gained a `&[FsParameter]` argument carrying the parameters whose value is a PINNED open file; `fuse::pinned_channel` consumes it, falling back to the fd-table lookup when the option arrived as `mount -o fd=N`. |
| `read(2)` on an fscontext fd returns `EINVAL`; the error log it should return is populated and unreachable (med) | FIXED. `FsContext::fetch_message` (ungated, tested) + `fsmount_common::fscontext_ops` wire it to the inode. One message per read, `ENODATA` on an empty ring, `EMSGSIZE` with the message LEFT QUEUED on a short buffer, byte count = entry length. Entries are now newline-terminated, which is the wire form. |
| `ClassicMountFsContextOps::get_tree` re-stamps `sb_flags` on a superblock `sget` REUSED rather than created (low) | FIXED. The re-stamp is gone. `sget_reused` reports whether the instance was reused, and `superblock_from_filesystem` refuses a reuse whose `SB_RDONLY` disagrees with EBUSY. The other `SB_*` bits are per-mount and are not stamped on a hit. |

## Found and fixed in the same pass (not previously curated)

| Sev | Issue |
|---|---|
| med | The superblock-flag rung was gated on a BARE WORD, so `mount -o ro=1` / `ro=0` fell through to the filesystem table and were reported unknown parameters. The reference keys that rung on the NAME alone and never looks at the value. Fixed; pinned by `a_superblock_flag_is_recognised_whatever_value_it_carries`. |
| med | `FileSystemType::mount_with_flags`'s default DROPPED the `SB_*` word for any backend implementing only `mount()`. It was masked by `get_tree`'s re-stamp; removing that re-stamp exposed it. The default now stamps at the fill-super compatibility boundary, where the instance is always freshly minted. |
| low | `FsParamType::String` accepted a pathname value, so `FSCONFIG_SET_PATH` on a string-typed key was silently taken as text. The reference refuses it. A filesystem that wants a pathname declares `Path`. |

## Deliberately NOT fixed here — reasons

| Sev | Issue | Why not this PR |
|---|---|---|
| high | `hidepid=` / `subset=pid` are not a table problem — procfs cannot express them at all; `proc_root()` is a process-global cached `Arc`, so every `mount -t proc` in every namespace shares ONE root inode. | Per-superblock procfs root inodes are a procfs-identity change, not a mount-API change: nothing in this PR's mechanism touches where per-mount state lives. It needs its own lane, and it interacts with `scratch/pseudo-inode-identity.md`. Unchanged here: `mount -t proc -o hidepid=2` still returns EINVAL, which stays the honest answer until the confinement is implemented. |
| high | `fsmount(2)` returns an anon-inode fd over a deferred mount object, not an `O_PATH` fd over a real vfsmount in an anonymous mount namespace. | Requires anonymous mount namespaces and a real detached `vfsmount` — a mount-namespace change of comparable size to this whole PR, sharing no code with the parameter mechanism. Own lane. |
| med | 17 of 22 registered filesystems publish no parameter table, so their options are accepted-and-ignored. | Closing it honestly means IMPLEMENTING each one's options, not declaring them: `devpts` `gid=`/`uid=`/`mode=` set new pty slave inode ownership and mode, `ptmxmode=` sets the ptmx node's mode (and is rewritten on remount), `max=` caps pty index allocation, `newinstance` is a no-op the reference keeps only so old userspace is not refused. `cgroup2` `nsdelegate`/`memory_recursiveprot` likewise. Each is its own enforcement lane; `devpts` is boot-critical (wrong = no ttys) and must not ride a parameter-plumbing PR. The semantics above are recorded so the next lane does not have to re-derive them. |
| low | A `mount(2)` LSM option (`context=`, `fscontext=`, `defcontext=`, `rootcontext=`) is refused by any filesystem that publishes a table. | Re-verified against the reference: the LSM rung returns "not my parameter" when no security module claims the key, and the option then falls to the filesystem table and is reported unknown. We register no module that claims them, so EINVAL is the correct answer for this configuration. It becomes a defect the moment a module that parses them is registered, not before. Row should be reworded rather than closed. |
| low | ext4 admits its whole ~90-name table and acts only on the quota family; `journal_path` is declared `Path` and ignored. | Accepted-but-ignored, and the fix is ext4 enforcement, not admission. Untouched by this PR. |

## Other findings

| Sev | Issue |
|---|---|
| low | `ipc` `futex_core_hosted::wait_timeout_returns_etimedout_not_a_fake_success` FLAKES under parallel load — it timed out once during a loaded `cargo test --workspace` and passed on two immediate re-runs and on every subsequent full run. Timing-sensitive, unrelated to this lane. |
| low | Restoring a source file from a `cp`-made backup gives it the BACKUP's mtime, which is older than the build artifact, so `cargo test` silently reuses the stale binary and a restored tree still reports the injected failure. Cost one false "the fix did not restore" during positive-control work here. `touch` the restored files. |
| low | `fsmount_common/fscontext_ops.rs` is `target_os = "oxide-kernel"`-gated, so its `FileOps::read` shim is not hosted-testable. All of its DECISION logic lives in the ungated `FsContext::fetch_message`, which is; the gated part is lock/ask/copy only. |
