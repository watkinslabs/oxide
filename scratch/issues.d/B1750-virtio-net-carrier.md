# B1750 — virtio-net carrier

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED B1750 | DEFECT | med | `net::netdev::set_iface_carrier` had no caller. Carrier was fixed at `true` from registration, so `IFF_RUNNING`/`IFF_LOWER_UP` were derived from a constant and no device could ever report a real link transition. virtio-net negotiates `VIRTIO_NET_F_STATUS` and then never read `virtio_net_config.status`. | `virtio::carrier_from_status` (3 hosted tests); the driver reads the status word and publishes carrier after registration | — |
| OPEN | MISSING | med | A `VIRTIO_NET_S_LINK_UP` change after probe is not observed: the reference handles the device's config-change interrupt and calls `netif_carrier_on`/`netif_carrier_off`, emitting `RTM_NEWLINK`. Ours samples the status once, at registration. | `crates/drivers/drv-virtio-net/src/modern/state.rs` publishes carrier only from `init_modern_with_rx_pool` | — |
| OPEN | INFRA | med | Guest serial RX duplicates characters on long typed lines — `sleep 1` arrived as `sleep 11`, `busctl` as `busscl`. Any diagnostic driven through the serial console must use short commands, and a probe that reads back a corrupted command produces a false result. | probe transcripts on `8dce885fd`: `dd`, `ee`, `ssleep`, `addd` | — |
