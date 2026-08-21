// Intel HD-Audio controller and codec driver.
//
// Module manifest:
// - `uapi`: controller register file, bit definitions, PCI class.
// - `verb`: codec command encoding, parameter ids, response decode.
// - `widget`: widget/pin/amplifier capability decode.
// - `defcfg`: pin default-configuration decode.
// - `connlist`: connection-list slot and range decode.
// - `graph`: widget-graph model and codec enumeration over a `CodecBus`.
// - `autocfg`: pin classification into output groups and capture sources.
// - `paths`: route search and per-route volume/mute ownership.
// - `generic`: converter assignment, badness scoring, the routing plan.
// - `ctlname`: mixer and jack control naming.
// - `stream_fmt`: stream-format encoding and PCM capability decode.
// - `bdl`: buffer descriptor list construction and ring arithmetic.
// - `ring`: CORB/RIRB pointer arithmetic.
// - `regs`,`transport`,`controller`,`stream`,`card`,`probe`: the kernel-only
//   MMIO, DMA, interrupt, ALSA-card and PCI-probe layers.

#![no_std]
// dead_code is meaningful for this crate ONLY on the kernel target: a large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// compiles a strict subset and calls live items dead.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

extern crate alloc;

pub mod uapi;
pub mod verb;
pub mod widget;
pub mod defcfg;
pub mod connlist;
pub mod graph;
pub mod autocfg;
pub mod paths;
pub mod generic;
pub mod ctlname;
pub mod stream_fmt;
pub mod bdl;
pub mod ring;
pub mod elemkey;
mod ownership;

#[cfg(target_os = "oxide-kernel")] mod platform;
#[cfg(target_os = "oxide-kernel")] pub mod regs;
#[cfg(target_os = "oxide-kernel")] pub mod transport;
#[cfg(target_os = "oxide-kernel")] pub mod stream;
#[cfg(target_os = "oxide-kernel")] pub mod controller;
#[cfg(target_os = "oxide-kernel")] pub mod card;
#[cfg(target_os = "oxide-kernel")] mod probe;

#[cfg(target_os = "oxide-kernel")]
pub use probe::{HdaDriver, HDA_DRIVER};

#[cfg(test)]
#[path = "tests/fixture.rs"]
mod fixture;
