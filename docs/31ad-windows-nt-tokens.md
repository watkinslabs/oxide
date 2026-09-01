# Windows native NT tokens

Status: FROZEN  
Frozen: 2026-08-31

## Contract

- `NtOpenProcessToken` and `NtOpenThreadToken` expose current-task primary-token snapshots through process-local NT handles.
- The token snapshots the existing task effective UID/GID; Linux credential ownership and capability checks remain in the Linux/security layers.
- `NtAdjustGroupsToken` can replace the bounded group list or restore the default group, without mutating Linux credentials.
- The current boundary rejects previous-state and return-length output buffers; richer privilege and SID semantics remain future work.
- `NtQueryInformationToken` supports the native basic UID/GID view and primary-token type view with exact output-length validation.
- Token handles require `TOKEN_QUERY` for queries and retain their own access mask and generation lifetime.

## Tests

- current process/thread targets and access masks are validated before a token handle is published;
- token objects retain immutable credential snapshots and reject stale or wrong-type handles;
- query output lengths, pointers, and supported information classes are validated;
- native NTDLL exports and append-only selectors are checked on both kernel architectures.
- group replacement preserves the UID/GID snapshot while changing NT membership state;
- malformed group counts, SID pointers, and lengths are rejected before mutation.
