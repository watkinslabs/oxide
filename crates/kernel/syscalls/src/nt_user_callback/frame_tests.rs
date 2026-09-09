//! Copied arguments cannot overlap the callback ABI frame or saved caller stack.
use super::*;
use alloc::vec::Vec;
struct Buffer { bytes: [u8; 512], fail: Option<usize>, writes: Vec<(u64, usize)> }
impl Buffer { fn new() -> Self { Self { bytes: [0xa5; 512], fail: None, writes: Vec::new() } } }
impl Memory for Buffer {
    fn write(&mut self, address: u64, bytes: &[u8]) -> bool {
        self.writes.push((address, bytes.len()));
        if self.fail == Some(self.writes.len()) { return false; }
        let Ok(start) = usize::try_from(address) else { return false; };
        let Some(end) = start.checked_add(bytes.len()) else { return false; };
        let Some(target) = self.bytes.get_mut(start..end) else { return false; };
        target.copy_from_slice(bytes); true
    }
}
#[test]
fn existing_user_pointer_keeps_the_direct_call_shape() {
    let mut memory = Buffer::new();
    let prepared = prepare(&mut memory, 0x1c8, Input::User { address: 0x1234, length: 17 }, 0x9876).unwrap();
    assert_eq!(prepared, Prepared { stack: 0x198, argument: 0x1234, length: 17 });
    assert_eq!(&memory.bytes[0x198..0x1a0], &0x9876u64.to_le_bytes());
    assert_eq!(&memory.bytes[0x1a0..0x1c0], &[0; 32]);
    assert!(memory.bytes[0x1c0..].iter().all(|byte| *byte == 0xa5));
}
#[test]
fn scrollbar_record_is_copied_below_the_caller_for_each_stack_alignment() {
    let record = [0x5c; 104];
    for stack in 0x1c0..0x1d0 {
        let mut memory = Buffer::new();
        let prepared = prepare(&mut memory, stack, Input::Record(&record), 0x9876).unwrap();
        assert_eq!(prepared.stack % 16, 8);
        assert_eq!(prepared.argument % 8, 0);
        assert!(prepared.argument >= prepared.stack + 40);
        assert!(prepared.argument + u64::from(prepared.length) <= stack);
        assert_eq!(&memory.bytes[prepared.argument as usize..prepared.argument as usize + 104], &record);
        assert!(memory.bytes[stack as usize..].iter().all(|byte| *byte == 0xa5));
    }
}
#[test]
fn underflow_and_failed_writes_never_admit_a_callback() {
    let mut memory = Buffer::new();
    assert_eq!(prepare(&mut memory, 47, Input::User { address: 0, length: 0 }, 1), None);
    assert!(memory.writes.is_empty());
    for fail in 1..=3 {
        let mut memory = Buffer::new(); memory.fail = Some(fail);
        assert_eq!(prepare(&mut memory, 0x1c8, Input::Record(&[0x5c; 104]), 1), None);
        assert_eq!(memory.writes.len(), fail);
    }
}
