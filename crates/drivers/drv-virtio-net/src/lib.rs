//! virtio-net driver per `34§*`. Transport-supplied MMIO queues plus net stack
//! integration.

#![no_std]

extern crate alloc;

#[cfg(any(test, target_os = "oxide-kernel"))]
pub mod modern;
