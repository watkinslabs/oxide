//! signal — glibc-ABI (docs/59§3, §6 G9). G9a: sigset_t ops (oracle) +
//! mask/kill/raise syscall wrappers. G9b adds sigaction + the
//! rt_sigreturn restorer trampoline + signal().
pub mod sigset;
pub mod sigaction;
#[cfg(feature = "freestanding")]
pub mod sig;
#[cfg(feature = "freestanding")]
pub mod desc;
#[cfg(feature = "freestanding")]
pub mod legacy;
