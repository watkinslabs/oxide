# B1759 — virtio-net config carrier changes

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| CLAIMED B1759 | DEFECT | med | A negotiated `VIRTIO_NET_F_STATUS` link change is never consumed after probe: the driver samples the config status once and has no config-change callback, so carrier and `RTM_NEWLINK` remain stale. | `modern/state.rs` publishes only from `init_modern_with_rx_pool`; `B1750` records the missing runtime transition. | B1759 |
