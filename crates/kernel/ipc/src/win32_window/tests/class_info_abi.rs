use super::*;
use crate::win32_window::ClassMenuName;

fn described() -> ClassDescription {
    ClassDescription { style: 0x0003, cb_wnd_extra: 8, cb_cls_extra: 4, background: 6, cursor: 0x1111, icon: 0x2222,
        icon_sm: 0x3333, module: 0x1400_0000, menu_name: ClassMenuName { ansi: 0x66, wide: 0x67, unicode_string: 0x68 } }
}

fn reply(ansi: bool) -> ClassInfoReply {
    ClassInfoReply { wndproc: 0x1_4000_42c0, cb_wnd_extra: 8, instance: 0x1_4000_0000, class_name: 0x7ffd_0000, ansi }
}

fn field(bytes: &[u8; BYTES], offset: usize) -> u64 { u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) }
fn word(bytes: &[u8; BYTES], offset: usize) -> u32 { u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) }

#[test]
fn the_menu_name_a_class_registered_reaches_the_caller() {
    let bytes = encode(&described(), &reply(false));
    assert_eq!(field(&bytes, 56), 0x67);
    let bytes = encode(&described(), &reply(true));
    assert_eq!(field(&bytes, 56), 0x66);
}

#[test]
fn a_class_registered_without_a_menu_name_reports_none() {
    let mut class = described();
    class.menu_name = ClassMenuName::default();
    assert_eq!(field(&encode(&class, &reply(false)), 56), 0);
}

#[test]
fn the_instance_lands_in_its_own_field_and_never_in_the_icon() {
    let bytes = encode(&described(), &reply(false));
    assert_eq!(field(&bytes, 24), 0x1_4000_0000);
    assert_eq!(field(&bytes, 32), 0x2222);
}

#[test]
fn every_remaining_field_carries_the_registered_value() {
    let bytes = encode(&described(), &reply(false));
    assert_eq!(word(&bytes, 0), BYTES as u32);
    assert_eq!(word(&bytes, 4), 0x0003);
    assert_eq!(field(&bytes, 8), 0x1_4000_42c0);
    assert_eq!(word(&bytes, 16), 4);
    assert_eq!(word(&bytes, 20), 8);
    assert_eq!(field(&bytes, 40), 0x1111);
    assert_eq!(field(&bytes, 48), 6);
    assert_eq!(field(&bytes, 64), 0x7ffd_0000);
    assert_eq!(field(&bytes, 72), 0x3333);
}
