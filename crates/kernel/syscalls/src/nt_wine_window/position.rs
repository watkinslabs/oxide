// Module manifest: ABI values, position planning, canonical kernel adapter, hosted contracts.
#[path = "position/abi.rs"] mod abi;
#[path = "position/policy.rs"] mod policy;
pub(crate) use abi::{Context, Request, Order, move_window_args};
#[cfg(target_os = "oxide-kernel")]
#[path = "position/kernel.rs"] mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use kernel::{set,plan_current};
#[cfg(test)]
#[path = "tests/position.rs"] mod tests;
#[cfg(all(test,not(target_os="oxide-kernel")))]
#[path = "../nt_window/position/layout.rs"] mod callback_layout;
#[cfg(all(test,not(target_os="oxide-kernel")))]
#[path = "../nt_window/position/work.rs"] mod remote_work;
