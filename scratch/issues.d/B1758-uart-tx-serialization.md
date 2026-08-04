# B1758 — UART TX serialization

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| CLAIMED B1758 2026-08-03 | DEFECT | med | The 16550 console has no port transaction lock: concurrent `emit` calls can both observe `LSR.THRE`, and `set_baud` can expose DLL/DLM while another emitter writes THR. Startup also never enables or clears the FIFOs. One UART-owned lock must serialize TX and divisor programming; startup must establish the FIFO state before RX interrupts are enabled. | `drv-uart-16550/src/lib.rs`: `emit`, `set_baud`, and `init`; measured serial echo duplication blocks trustworthy guest probes. | B1758-uart-tx-serialization |
