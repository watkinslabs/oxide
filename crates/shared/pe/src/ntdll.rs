// Module manifest: contracts shared by the PE loader and the native NTDLL adapter.
// environment: process-environment block entry parsing.
// syscalls: which NTDLL exports leave user mode, and which are library code.
// stub: decoding a shipped system-service stub body: ordinal and syscall-entry flag.
#[path = "ntdll/environment.rs"] mod environment;
pub use environment::environment_entry_value;
#[path = "ntdll/syscalls.rs"] pub mod syscalls;
#[path = "ntdll/stub.rs"] pub mod stub;
