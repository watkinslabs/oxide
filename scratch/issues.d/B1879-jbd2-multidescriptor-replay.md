# B1879 JBD2 multi-descriptor replay

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| OPEN | DEFECT | high | **JBD2 checksum journal formats are not implemented end to end.** Recovery neither verifies descriptor tails, per-tag data checksums, nor commit checksums, and its tag iterator only models the unchecksummed 8/12-byte layouts. Writeback falls back to direct home writes for `CSUM_V2`/`CSUM_V3` but does not gate the compatible v1 checksum feature. A checksum-enabled recovery log can therefore be misparsed or accepted after corruption instead of receiving checksum validation. | `replay` consults only `JBD2_INCOMPAT_64BIT` while parsing tags and performs no checksum calculation; `commit_metadata` gates `JBD2_INCOMPAT_CSUM_V2|CSUM_V3` only. The checked-in journal fixture and Firefox root image report no journal checksum features, so this is not the B1878 failure. | — |
