// Module manifest: contracts shared by the PE loader and the native NTDLL adapter.
// environment: process-environment block entry parsing.
// syscalls: which NTDLL exports leave user mode, and which are library code.
// stub: decoding a shipped system-service stub body: ordinal and syscall-entry flag.
// services: walking a shipped module for every service stub and its ordinal.
#[path = "ntdll/environment.rs"] mod environment;
pub use environment::environment_entry_value;
#[path = "ntdll/syscalls.rs"] pub mod syscalls;
#[path = "ntdll/stub.rs"] pub mod stub;
#[path = "ntdll/services.rs"] pub mod services;
