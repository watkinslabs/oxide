use super::*;

#[test]
fn nccalc_pointer_relocates_inside_owned_callback_frame() {
    let input = [0x55; 96];
    let p = prepare(0x10008, &input, &[(48, 56)]).unwrap();
    assert_eq!(p.stack & 15, 8);
    assert_eq!(p.address & 15, 0);
    assert_eq!(p.address - p.stack, 40);
    assert!(p.address + p.bytes.len() as u64 <= 0x10008);
    assert_eq!(u64::from_le_bytes(p.bytes[48..56].try_into().unwrap()), p.address + 56);
    assert_eq!(&p.bytes[56..], &input[56..]);
    assert_eq!(input, [0x55; 96]);
}

#[test]
fn malformed_payload_or_relocation_cannot_produce_a_frame() {
    assert!(prepare(32, &[0; 96], &[]).is_none());
    assert!(prepare(0x10008, &[], &[]).is_none());
    assert!(prepare(0x10008, &[0; MAX_PAYLOAD + 1], &[]).is_none());
    assert!(prepare(0x10008, &[0; 96], &[(89, 56)]).is_none());
    assert!(prepare(0x10008, &[0; 96], &[(48, 96)]).is_none());
}
