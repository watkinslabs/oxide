# KI-0340 audit

Status | Branch | Finding
---|---|---
verified | feat/windows-metadata-only-open-20260905 | KI-0340 implementation is already in `origin/main`; this branch records the independent audit and executable evidence.

## 1

Reference behavior checked before conclusion:

- `DesiredAccess == 0` is a valid metadata-only file open.
- A metadata-only open does not participate in ordinary read/write/delete share conflicts, and its requested share mask is ignored.
- The handle retains no data access; later operations must use the granted access mask.

Current-tree owners match that contract:

- `nt_file_policy::access_mask_admits_open` admits zero access and rejects an unsupported access class.
- `nt_file::open_path` applies the predicate before VFS open and inserts the original desired mask plus synchronization access.
- `vfs::WindowsShareContext` is the single inode-owned share state; its metadata-only branch bypasses ordinary share conflicts while preserving mapping conflicts.

## 2

Hosted evidence:

- `cargo test -p syscalls --lib nt_file_policy -- --test-threads=1`: 11 passed, 0 failed.
- `cargo test -p vfs --features hosted,sched/hosted --lib windows_share -- --test-threads=1`: 6 passed, 0 failed.
- Positive control: changing the metadata-only branch to report a conflict made `metadata_only_open_ignores_requested_share_mode` fail (exit 101).
- Restored branch: the same focused VFS suite returned 6 passed, 0 failed.

No boot was run: this audit changes no boot-visible code; hosted tests exercise the ungated policy and canonical share owner.
