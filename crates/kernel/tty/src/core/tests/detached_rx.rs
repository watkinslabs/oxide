use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::vec::Vec;

use super::{TtyDriver, TtyStruct};
use crate::ldisc::Sig;
use crate::wait::TtyWait;

static DOMAIN: Mutex<()> = Mutex::new(());
static IRQ_DEPTH: AtomicUsize = AtomicUsize::new(0);
static INLINE_CALLS: AtomicUsize = AtomicUsize::new(0);
static OUTPUT: Mutex<(usize, Vec<u8>)> = Mutex::new((0, Vec::new()));

struct ProbeIrq;

impl sync::IrqGate for ProbeIrq {
    unsafe fn save_disable() -> u64 { IRQ_DEPTH.fetch_add(1, Ordering::SeqCst) as u64 }
    unsafe fn save_enable() -> u64 { IRQ_DEPTH.swap(0, Ordering::SeqCst) as u64 }
    unsafe fn restore(flags: u64) { IRQ_DEPTH.store(flags as usize, Ordering::SeqCst); }
}

struct ProbeWait;

impl TtyWait for ProbeWait {
    type Irq = ProbeIrq;
    fn park_prepare(&self) {}
    fn park_abort(&self) {}
    fn park_commit(&self) {}
    fn wake_all(&self) {}
}

struct ProbeDriver;

fn detached(bytes: &[u8]) {
    assert_eq!(IRQ_DEPTH.load(Ordering::SeqCst), 0, "detached RX sink ran with IRQs masked");
    let mut out = OUTPUT.lock().unwrap();
    out.0 += 1;
    out.1.extend_from_slice(bytes);
}

impl TtyDriver for ProbeDriver {
    fn write(&mut self, _bytes: &[u8]) {
        INLINE_CALLS.fetch_add(1, Ordering::SeqCst);
    }
    fn signal_fg_pgrp(&mut self, _sig: Sig) {}
    fn detached_sink() -> Option<fn(&[u8])> { Some(detached) }
}

#[test]
fn rx_echo_uses_one_detached_emit_after_irq_restore() {
    let _domain = DOMAIN.lock().unwrap();
    IRQ_DEPTH.store(0, Ordering::SeqCst);
    INLINE_CALLS.store(0, Ordering::SeqCst);
    *OUTPUT.lock().unwrap() = (0, Vec::new());

    let tty = TtyStruct::new(ProbeDriver, ProbeWait);
    tty.receive_from_driver(b"hi\n");

    let out = OUTPUT.lock().unwrap();
    assert_eq!(INLINE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(out.0, 1);
    assert_eq!(&out.1, b"hi\r\n");
    assert_eq!(IRQ_DEPTH.load(Ordering::SeqCst), 0);
}
