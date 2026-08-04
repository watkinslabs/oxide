# B1759 — virtio-net config carrier changes

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED b2669b8ad | DEFECT | med | A negotiated `VIRTIO_NET_F_STATUS` link change was never consumed after probe, leaving carrier and `RTM_NEWLINK` stale. | The config vector now defers status refresh to the network bottom half; changed carrier state emits exactly one link notification. Unit tests cover status refresh and notification behavior; serial smokes pass on x86 and arm. | B1759 |
