# B1774 — virtio per-driver queue minima

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | DEFECT | med | Enforce each virtio driver's minimum descriptor count before it publishes ids outside the device's negotiated queue size. | The shared transport accepted any nonzero queue while VSOCK RX needs 8, blk needs 3, and GPU's display query uses descriptors 0 through 3. | unowned |
