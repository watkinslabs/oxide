use core::sync::atomic::{AtomicU64, Ordering};

use super::FdTable;

pub const OP_ALLOC: u64 = 1;
pub const OP_RESERVE: u64 = 2;
pub const OP_INSTALL: u64 = 3;
pub const OP_CANCEL: u64 = 4;
pub const OP_CLOSE: u64 = 5;
pub const OP_DUP: u64 = 6;
pub const OP_DUP2: u64 = 7;
pub const OP_DUP3: u64 = 8;
pub const OP_CLOSE_EXEC: u64 = 9;
pub const OP_CLOSE_RANGE: u64 = 10;
pub const OP_UNSHARE: u64 = 11;
pub const OP_CLONE_SHARED: u64 = 12;
pub const OP_CLONE_PRIVATE: u64 = 13;
pub const OP_CLOSE_CALL: u64 = 14;

const EVENT_CAPACITY: usize = 2048;
const WATCH_FD: i32 = 1;

struct Event {
    sequence: AtomicU64,
    table: AtomicU64,
    operation: AtomicU64,
    first: AtomicU64,
    second: AtomicU64,
    object: AtomicU64,
}

impl Event {
    const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            table: AtomicU64::new(0),
            operation: AtomicU64::new(0),
            first: AtomicU64::new(0),
            second: AtomicU64::new(0),
            object: AtomicU64::new(0),
        }
    }
}

static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static EVENTS: [Event; EVENT_CAPACITY] = [const { Event::new() }; EVENT_CAPACITY];

pub fn record(table: &FdTable, operation: u64, first: i32, second: i32) {
    record_object(table, operation, first, second, 0);
}

pub fn record_object(table: &FdTable, operation: u64, first: i32, second: i32, object: u64) {
    let descriptor_event = first == WATCH_FD
        || matches!(operation, OP_DUP | OP_DUP2 | OP_DUP3) && second == WATCH_FD;
    let table_event = matches!(operation, OP_UNSHARE | OP_CLONE_SHARED | OP_CLONE_PRIVATE);
    if !descriptor_event && !table_event { return; }
    let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let event = &EVENTS[sequence as usize % EVENT_CAPACITY];
    event.table.store(table as *const FdTable as u64, Ordering::Relaxed);
    event.operation.store(operation, Ordering::Relaxed);
    event.first.store(first as u32 as u64, Ordering::Relaxed);
    event.second.store(second as u32 as u64, Ordering::Relaxed);
    event.object.store(object, Ordering::Relaxed);
    event.sequence.store(sequence, Ordering::Release);
}

fn operation_name(operation: u64) -> &'static [u8] {
    match operation {
        OP_ALLOC => b"alloc",
        OP_RESERVE => b"reserve",
        OP_INSTALL => b"install",
        OP_CANCEL => b"cancel",
        OP_CLOSE => b"close",
        OP_DUP => b"dup",
        OP_DUP2 => b"dup2",
        OP_DUP3 => b"dup3",
        OP_CLOSE_EXEC => b"close-exec",
        OP_CLOSE_RANGE => b"close-range",
        OP_UNSHARE => b"unshare",
        OP_CLONE_SHARED => b"clone-shared",
        OP_CLONE_PRIVATE => b"clone-private",
        OP_CLOSE_CALL => b"close-call",
        _ => b"unknown",
    }
}

pub fn dump(table: &FdTable) {
    let table_address = table as *const FdTable as u64;
    let end = NEXT_SEQUENCE.load(Ordering::Acquire);
    let start = end.saturating_sub(EVENT_CAPACITY as u64);
    for sequence in start..end {
        let event = &EVENTS[sequence as usize % EVENT_CAPACITY];
        if event.sequence.load(Ordering::Acquire) != sequence
            || event.table.load(Ordering::Relaxed) != table_address
        {
            continue;
        }
        klog::write_raw(b"[FDHIST seq=");
        klog::write_dec_u64(sequence);
        klog::write_raw(b" op=");
        klog::write_raw(operation_name(event.operation.load(Ordering::Relaxed)));
        klog::write_raw(b" a=");
        klog::write_dec_u64(event.first.load(Ordering::Relaxed));
        klog::write_raw(b" b=");
        klog::write_dec_u64(event.second.load(Ordering::Relaxed));
        klog::write_raw(b" object=");
        klog::write_hex_u64(event.object.load(Ordering::Relaxed));
        klog::write_raw(b"]\n");
    }
}
