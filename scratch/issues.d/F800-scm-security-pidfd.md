# F800 — socket security and pidfd ancillary receive

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED e0a400d16 | MISSING | med | `SO_PASSSEC`/`SCM_SECURITY` and `SO_PASSPIDFD`/`SCM_PIDFD` were not emitted by the shared receive path; netlink had no `SO_PASSSEC` state. | Unix and netlink now retain the send-time security label with each queued record; one `recv_control` owner emits credentials, labels, rights, then pidfds. `SCM_PIDFD` reserves and commits its descriptor only after cmsg copyout. Focused security, net SCM, netlink, and receive-control tests plus both kernel-target checks pass. | F800-scm-security-pidfd |
