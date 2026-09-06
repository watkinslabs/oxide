//! Production adapter boundary assertions; hosted owners only record supplied arguments.
use super::*;
const CHILD: u64 = 0x4000_0000;
const POPUP: u64 = 0x8000_0000;

#[test]
fn child_full_width_hmenu_is_control_id_without_menu_validation() {
    let mut args = input(); args.a4 = CHILD; args.a0 = 0x7fa6_0000_0200;
    let id = 0xfedc_ba98_7654_3210;
    STATE.with(|s| { let mut s = s.borrow_mut(); s.stack[9] = 7; s.stack[10] = id; s.fail_menu = true; });
    assert_eq!(raw_class::create_window(args), 42);
    STATE.with(|s| { let s = s.borrow();
        assert_eq!(s.class, Some((21, 7)));
        assert_eq!(s.metadata, Some((42, CHILD as u32, 0x200, 0)));
        assert_eq!(s.control_id, Some((42, id)));
        assert_eq!(s.menu, None);
        assert_eq!(s.creation.unwrap().menu, id);
        assert_eq!(s.destroyed, 0);
    });
}

#[test]
fn popup_wins_over_child_for_parent_owner_and_menu() {
    for style in [POPUP, CHILD | POPUP] {
        let mut args = input(); args.a4 = style;
        STATE.with(|s| { let mut s = s.borrow_mut(); s.stack[9] = 7; s.stack[10] = 9; });
        assert_eq!(raw_class::create_window(args), 42);
        STATE.with(|s| { let s = s.borrow();
            assert_eq!(s.class, Some((21, 0)));
            assert_eq!(s.metadata, Some((42, style as u32, 0, 7)));
            assert_eq!(s.menu, Some(9));
            assert_eq!(s.control_id, None);
            assert_eq!(s.creation.unwrap().parent, 7);
        });
    }
}

#[test]
fn combined_popup_child_rejects_full_width_menu_as_top_level() {
    let mut args = input(); args.a4 = CHILD | POPUP;
    STATE.with(|s| { let mut s = s.borrow_mut(); s.stack[9] = 7; s.stack[10] = 0x1_0000_0001; });
    assert_eq!(raw_class::create_window(args), 0);
    STATE.with(|s| { let s = s.borrow(); assert_eq!(s.control_id, None); assert_eq!(s.destroyed, 1); });
}

#[test]
fn register_cbwndextra_twenty_reaches_canonical_registration() {
    let mut args = input(); args.a0 = 0x1234_0000; args.a5 = 0;
    STATE.with(|s| { let mut s = s.borrow_mut(); s.wndclass = args.a0; s.extra = 20; s.class_style = 0x83; });
    assert_eq!(raw_class::register_class(args), 21);
    STATE.with(|s| { let s = s.borrow();
        assert_eq!(s.registered, Some((vec![78], 0x1400042c0, 20)));
        assert_eq!(s.user_reads, vec![args.a0, args.a0 + 20, args.a0 + 4]);
        assert_eq!(s.registered_style, Some(0x83));
        assert_eq!(s.registered_unicode, Some(true));
    });
}
#[test]
fn register_encoding_uses_low_dword_ansi_flag() {
    for (flag,unicode) in [(0,true),(1,false),(0x7fa6_0000_0000,true),(0x7fa6_0000_0001,false)] {
        let mut args=input();args.a0=0x1234_0000;args.a5=flag;
        STATE.with(|s|{let mut s=s.borrow_mut();s.wndclass=args.a0;s.extra=20;});
        assert_eq!(raw_class::register_class(args),21);
        STATE.with(|s|assert_eq!(s.borrow().registered_unicode,Some(unicode)));
    }
}
