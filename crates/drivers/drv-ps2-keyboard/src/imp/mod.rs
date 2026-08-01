// Real i8042 PS/2 keyboard device. x86_64 kernel target only.
//
// Module manifest:
// * `regs` — i8042 port numbers, status bits, controller/device commands and
//   command-byte config bits. Hardware contract only, no logic.
// * `state` — driver-lifetime atomics (detection, IRQ vector/pin, boot platform
//   data) and the predicates that read them.
// * `ports` — bounded CPL=0 port-I/O primitives against 0x60/0x64.
// * `bringup` — controller + keyboard bring-up, IRQ-bit policy, and the
//   quiesce/teardown sequences.
// * `irq` — IRQ1 I/O APIC programming and the IRQ-context scancode drain.
// * `driver` — `drv::Driver` registration for the platform/i8042 device.

mod regs;
mod state;
mod ports;
mod bringup;
mod irq;
mod driver;

pub use driver::driver;
pub use state::{configure_probe, present};
