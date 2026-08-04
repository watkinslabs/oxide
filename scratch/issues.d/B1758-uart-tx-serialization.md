# B1758 — UART TX serialization

| Status | Class | Sev | Issue | Evidence | Owner |
|---|---|---|---|---|---|
| FIXED ccca25489 | DEFECT | med | The 16550 console had no port transaction lock: concurrent `emit` calls could both observe `LSR.THRE`, and `set_baud` could expose DLL/DLM while another emitter wrote THR. Startup also never enabled or cleared the FIFOs. Both UART backends now serialize TX and divisor programming with an IRQ-safe port lock; 16550 startup clears and enables its FIFO before RX interrupts. | `drv-uart-16550` hosted FIFO test; both-arch `make smoke`; x86 serial-only long command stress probe passed. | — |
