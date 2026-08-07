| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| CLAIMED | COVERAGE | low | The recorded `/proc/keys` integration-test flake is stale: its process-wide key-store mutex already serializes every mutating test in the binary. | `cargo test -p fs --test keyring_procfs` passed 30 consecutive runs (120 test executions). | D515-archive-keyring-procfs-flake |
