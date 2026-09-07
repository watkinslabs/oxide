// Module manifest: contracts shared by the PE loader and the native NTDLL adapter.
// environment: process-environment block entry parsing.
// syscalls: which NTDLL exports leave user mode, and which are library code.
#[path = "ntdll/environment.rs"] mod environment;
pub use environment::environment_entry_value;
#[path = "ntdll/syscalls.rs"] pub mod syscalls;
