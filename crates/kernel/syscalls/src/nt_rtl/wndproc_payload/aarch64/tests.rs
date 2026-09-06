use super::*;

const USER_END: u64 = 1 << 47;

#[test]
fn relocated_payload_is_above_arm_stack_and_result_spill() {
    let bytes = [0x55; 96];
    let p = prepare(0x10000, &bytes, &[(48,56)], USER_END).unwrap();
    assert_eq!(p.stack & 15, 0); assert_eq!(p.stack, p.address);
    assert!(p.address + p.bytes.len() as u64 <= 0x10000);
    assert_eq!(u64::from_le_bytes(p.bytes[48..56].try_into().unwrap()), p.address + 56);
    assert_eq!(&p.bytes[56..], &bytes[56..]); assert_eq!(bytes, [0x55;96]);
}

#[test]
fn bad_payload_alignment_and_relocations_fail() {
    for sp in [0,16,32,0x10008,USER_END + 16] { assert!(prepare(sp,&[0;96],&[],USER_END).is_none()); }
    assert!(prepare(0x10000,&[],&[],USER_END).is_none());
    assert!(prepare(0x10000,&[0;4097],&[],USER_END).is_none());
    for relocation in [(89,56),(48,96),(usize::MAX,0)] {
        assert!(prepare(0x10000,&[0;96],&[relocation],USER_END).is_none());
    }
}

#[test]
fn handoff_preserves_saved_lr_and_delivers_hwnd_through_retval() {
    let saved = Control { pc: 0x1110, sp: 0x10000, lr: 0x2220 };
    let p = prepare(saved.sp,&[0;96],&[],USER_END).unwrap();
    let h = handoff(saved,&p,0x3330,0x4440,123,0x83,9,USER_END).unwrap();
    assert_eq!(h.saved,saved); assert_eq!(h.entry,Control {pc:0x3330,sp:p.stack,lr:0x4440});
    assert_eq!(h.arguments,[123,0x83,9,p.address]); assert_eq!(h.syscall_result,123);
}

#[test]
fn bad_entry_and_forged_payload_cannot_form_handoff() {
    let saved = Control { pc: 0x1110, sp: 0x10000, lr: 0x2220 };
    let mut p = prepare(saved.sp,&[0;96],&[],USER_END).unwrap();
    for target in [0,1,USER_END,u64::MAX] {
        assert!(handoff(saved,&p,target,0x4440,123,0,0,USER_END).is_none());
        assert!(handoff(saved,&p,0x3330,target,123,0,0,USER_END).is_none());
    }
    p.stack += 8;
    assert!(handoff(saved,&p,0x3330,0x4440,123,0,0,USER_END).is_none());
}
