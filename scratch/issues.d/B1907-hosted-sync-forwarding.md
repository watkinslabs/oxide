| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| CLAIMED | DEFECT | low | Hosted scheduler builds did not forward `sync/hosted`, so contended scheduler locks could pure-spin while their host-thread owner was descheduled. `klog` has no `sync` dependency and no lock using this behavior, so it requires no forwarding. | `sched/Cargo.toml` `hosted`; feature graph must show `sync/hosted` under `sched --features hosted`. | B1907-hosted-sync-forwarding |
