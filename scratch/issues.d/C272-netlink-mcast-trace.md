# C272 — rtnetlink multicast delivery trace

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED C272 | INFRA | med | A notification nobody received was indistinguishable from one never sent: nothing reported which sockets existed, which were subscribed, or how many the message reached. Three DNS investigations theorized delivery bugs that this would have refuted in one boot. | `debug-netlink` now emits `[NL-MCAST ns= grp= live= subscribed= reached= type= bytes=]` per broadcast and `[NL-SUB tid/comm proto= add=/bindmask=]` per subscription | — |
| CLOSED C272 | — | — | Negative result, recorded so it is not re-investigated: rtnetlink multicast delivery to systemd-resolved is CORRECT. resolved subscribes via `NETLINK_ADD_MEMBERSHIP` to groups 1, 5 and 9 exactly as its source does, and every address and link notification reaches it (`subscribed=2 reached=2`, 63/63 events). Multicast group numbering, the group-number-vs-bitmask convention, membership storage and the listener registry are all sound. | trace boot on `d7d0d5f9b` | — |
