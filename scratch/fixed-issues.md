# Fixed issues

Archive of rows retired from `scratch/known_issues.md`. A row moves here only
when the fix is merged; the SHA stays with it. Kept so a later lane can see what
shape these defects took — several were subsystems that compiled, tested and
shipped with nothing calling them.

Columns match the live ledger: `Status | Sev | Issue | Evidence | Owner`.

## Keyring

| Status | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|
| FIXED 579d405bd | high | `inherit_session` had NO caller outside its own test. No forked child ever inherited a session keyring; nothing purged a dead task's entries, so a RECYCLED tid inherited the previous occupant's keys, and every task touching `@s`/`@t`/`@p` leaked a keyring plus its quota charge permanently. | B1649. Now `lifecycle::{fork,exec,exit,fsids_changed}` wired at clone/execve/exit/commit_creds; `exit_purges_the_tid_and_frees_the_keyring`, `exit_refunds_the_quota_charge`. | B1649 |
| FIXED 244c9e5f6 | high | Between minting an authorisation token and handing the helper the keyring holding it, NEITHER was reachable from any gc root. Any concurrent `collect()` — an unrelated task unlinking a key is enough — destroyed both and stranded the requester on a key no helper could then answer. A real intermittent production failure, surfaced only because the hosted tests run in parallel against the global store. | B1649. `Store::collect` now roots live tokens and the keyring linking them. | B1649 |
| FIXED 244c9e5f6 | high | `KEYCTL_GET_PERSISTENT` aliased the USER keyring — wrong owner, wrong lifetime (the user keyring dies with the last session; the persistent one must outlive logout), and gated on `CAP_SYS_ADMIN` where the reference uses `CAP_SETUID`. | B1649. Now a real `_persistent.<uid>` in a `.persistent_register`, destination mandatory, expiry refreshed per use; `the_persistent_keyring_is_not_the_user_keyring`. | B1649 |
| FIXED 244c9e5f6 | high | `KEYCTL_SEARCH` flattened every failure to ENOKEY, discarding WHY the search failed. That both hid EACCES/EKEYREVOKED/EKEYEXPIRED from callers and made negative-key caching impossible, so an unresolvable name would re-run the helper on every request. Three pre-existing tests asserted the flattened behaviour and encoded the wrong belief. | B1649. `ops/search.rs` now reproduces the skip-reason propagation and the `success > ENOKEY > EAGAIN > other` merge. | B1649 |
| FIXED 244c9e5f6 | med | `request_key` did not distinguish `callout == NULL` from `callout == ""`; both suppressed construction. The empty string must upcall. | B1649, `an_empty_callout_string_still_upcalls`. | B1649 |
| FIXED 244c9e5f6 | med | `KEYCTL_REVOKE` did not retry with `KEY_NEED_SETATTR` on EACCES, so a key whose mask grants Setattr but not Write could not be withdrawn by its holder; and it used a partial lookup, so a second revoke reported EACCES instead of EKEYREVOKED. | B1649, `revoke_falls_back_to_setattr_permission`, `revoking_twice_reports_the_key_is_already_revoked`. | B1649 |
| FIXED 244c9e5f6 | med | `KEYCTL_SET_TIMEOUT` and `KEYCTL_GET_SECURITY` had no authorisation-token path, so a helper could not bound or inspect the key it was asked to build. `KEYCTL_JOIN_SESSION_KEYRING` accepted a `.`-prefixed name, which would place a caller inside `.persistent_register`. | B1649, `set_timeout_accepts_the_authorisation_token_instead_of_setattr`, `a_dot_prefixed_session_name_is_refused`. | B1649 |
| FIXED 68f197dc4 | med | `/proc/keys` and `/proc/key-users` were empty static stubs and `/proc/sys/kernel/keys/*` did not exist at all. | B1649. Both live and per-reader filtered; four ceilings plus `persistent_keyring_expiry` bound to the live values `key_alloc` and `KEYCTL_GET_PERSISTENT` consult. | B1649 |
