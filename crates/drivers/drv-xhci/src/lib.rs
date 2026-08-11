//! xHCI host-controller contract: capability geometry and register ownership.
//!
//! Module manifest:
//! - `regs`: xHCI capability decoding and validated register-file geometry.
//! - `ring`: command and event TRB ownership/cycle mechanics.
//! - `controller`: reset/run register sequencing and DMA register plan.

#![no_std]

pub mod regs;
pub mod ring;
pub mod controller;
