#![allow(unused_imports)]
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use sync::{Socket as SockLockClass, Spinlock};
use super::*;

static STORE_LOCK: Spinlock<(), SockLockClass> = Spinlock::new(());
fn store_guard() -> sync::Guard<'static, (), SockLockClass> { STORE_LOCK.lock() }

#[path = "tests/store.rs"] mod store;
#[path = "tests/eval.rs"] mod eval_tests;
#[path = "tests/netlink.rs"] mod netlink_tests;
