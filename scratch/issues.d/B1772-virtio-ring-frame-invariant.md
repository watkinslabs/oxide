# B1772 — virtio ring-frame invariant

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | DEFECT | med | Enforce the one-frame split-virtqueue capacity invariant at every driver handoff, not only while programming a queue. | `VirtQueueResource::is_runtime_valid` admitted any nonzero size even though driver ring-pointer proofs rely on the one-frame allocation made by `queue_cfg::program_queue`. | unowned |
