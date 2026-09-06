use super::*;
#[test]
fn callback_router_accepts_only_position_completion_kinds() {
    for kind in [CHANGING,NCCALC,CHANGED] {assert!(handles_callback(kind));}
    for kind in [0,1,2,3,4,5,CHANGING-1,CHANGED+1,u64::MAX] {assert!(!handles_callback(kind));}
}
fn request()->Request {Request {hwnd:7,rect:WindowRect {left:-3,top:4,right:97,bottom:54},order:Some(Order::NotTopmost),visible:None,flags:NOSIZE|NOSENDCHANGING}}
#[test]
fn windowpos_is_40_bytes_with_64bit_handles_and_flags_at32() {
    let p=request();let bytes=encode(p);assert_eq!(bytes.len(),40);
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()),u64::MAX-1);
    assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()),p.flags);
    assert_eq!(decode(&bytes,p.hwnd),Some([7,u64::MAX-1,(-3i32) as u32 as u64,4,100,50,p.flags as u64]));
}
#[test]
fn changing_cannot_replace_target_hwnd_but_can_change_geometry() {
    let p=request();let mut bytes=encode(p);bytes[16..20].copy_from_slice(&22i32.to_le_bytes());
    assert_eq!(decode(&bytes,p.hwnd).unwrap()[2],22);
    bytes[..8].copy_from_slice(&99u64.to_le_bytes());assert!(decode(&bytes,p.hwnd).is_none());
}
#[test]
fn nccalc_client_rect_rejects_reversed_and_overflowed_bounds() {
    let p=request();assert_eq!(decode_rect(encode_rect(p.rect)),Some(p.rect));
    for r in [WindowRect {left:1,top:0,right:0,bottom:0},WindowRect {left:i32::MIN,top:0,right:i32::MAX,bottom:0}] {
        assert!(decode_rect(encode_rect(r)).is_none());
    }
    assert_eq!(NCCALC_POINTER,48);assert_eq!(NCCALC_WINPOS,56);assert_eq!(NCCALC_BYTES,96);
}
