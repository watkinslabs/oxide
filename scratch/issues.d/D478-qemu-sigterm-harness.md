# D478 — QEMU SIGTERM harness

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| CLAIMED | INFRA | high | Isolated QEMU smoke probes are terminated by an external `claude` process before they can complete, preventing trustworthy guest DNS and D-Bus measurements. | Two x86 runs from separate worktrees ended `qemu-system-x86_64: terminating on signal 15 from pid 2698741 (claude)`; one had no valid probe result and the other showed `systemd-resolved.service` failed before termination. | D478-qemu-sigterm-harness |
