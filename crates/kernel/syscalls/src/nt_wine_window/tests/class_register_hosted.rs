//! Hosted execution of the production WNDCLASSEXW registration entry: every
//! field of the caller's structure must reach the canonical class owner.
use std::cell::RefCell;
use ipc::win32_window::class_info_abi as abi;

#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct SyscallArgs { a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64 }

/// The class name this harness's counted-string reader resolves.
const NAME_POINTER: u64 = 0x7ffe_4ba0_a3d0;
const NAME: u16 = 78;
const WNDCLASS_POINTER: u64 = 0x1234_0000;
const MENU_RECORD: u64 = 0x7ffe_4ba0_b000;
/// `MAKEINTRESOURCEW` of the menu the shipped editor names on its class.
const INT_RESOURCE_MENU: u64 = 0x201;
const WNDPROC: u64 = 0x1_4000_42c0;
const ATOM: u64 = 21;

#[derive(Default)]
struct State { wndclass: u64, fields: Vec<(usize, u64)>, size: u32,
    registered: Option<Registration>, faults: bool }

/// Everything the entry handed the canonical owner.
#[derive(Default)]
struct Registration { name: Vec<u16>, wndproc: u64, style: u32, cb_cls_extra: i32, cb_wnd_extra: i32,
    unicode: bool, background: u64, cursor: u64, icon: u64, icon_sm: u64, module: u64, builtin: bool,
    menu_name: u64 }

thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

macro_rules! wine_window_diag { ($($body:tt)*) => { { $($body)* } }; }

mod klog {
    pub fn write_raw(_: &[u8]) {}
    pub fn write_hex_u64(_: u64) {}
}

mod uaccess {
    use super::{STATE, abi};
    pub fn copy_from_user(destination: &mut [u8], address: u64) -> Result<(), ()> {
        STATE.with(|s| {
            let s = s.borrow();
            if s.faults || address != s.wndclass || destination.len() != abi::BYTES { return Err(()); }
            let mut raw = [0u8; abi::BYTES];
            raw[abi::SIZE..abi::SIZE + 4].copy_from_slice(&s.size.to_le_bytes());
            for (offset, value) in &s.fields {
                let width = if *offset == abi::STYLE || *offset == abi::CLS_EXTRA || *offset == abi::WND_EXTRA { 4 } else { 8 };
                raw[*offset..*offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
            }
            destination.copy_from_slice(&raw);
            Ok(())
        })
    }
}

fn read_unicode_string(pointer: u64) -> Option<Vec<u16>> { (pointer == NAME_POINTER).then_some(vec![NAME]) }

mod nt_window {
    use super::{ATOM, Registration, STATE};
    pub fn register_class_desc_for_current(desc: ipc::win32_window::ClassRegistration<'_>) -> Option<u64> {
        STATE.with(|s| s.borrow_mut().registered = Some(Registration { name: desc.name.to_vec(), wndproc: desc.wndproc,
            style: desc.style, cb_cls_extra: desc.cb_cls_extra, cb_wnd_extra: desc.cb_wnd_extra, unicode: desc.unicode,
            background: desc.background, cursor: desc.cursor, icon: desc.icon, icon_sm: desc.icon_sm,
            module: desc.module, builtin: desc.builtin, menu_name: desc.menu_name }));
        Some(ATOM)
    }
}
#[path = "../raw_class/register.rs"] mod register;

fn armed(fields: &[(usize, u64)]) -> SyscallArgs {
    STATE.with(|s| { let mut s = s.borrow_mut(); *s = State::default();
        s.wndclass = WNDCLASS_POINTER; s.size = abi::BYTES as u32;
        s.fields = fields.to_vec(); s.fields.push((abi::WNDPROC, WNDPROC)); });
    SyscallArgs { a0: WNDCLASS_POINTER, a1: NAME_POINTER, ..Default::default() }
}

fn registered<T>(read: impl FnOnce(&Registration) -> T) -> T {
    STATE.with(|s| read(s.borrow().registered.as_ref().expect("registration must reach the class owner")))
}

#[test]
fn every_wndclassexw_field_reaches_the_canonical_registration() {
    let args = armed(&[(abi::STYLE, 0x83), (abi::CLS_EXTRA, 16), (abi::WND_EXTRA, 20),
        (abi::INSTANCE, 0x1_4000_0000), (abi::ICON, 0x2222), (abi::CURSOR, 0x1111),
        (abi::BACKGROUND, 6), (abi::ICON_SM, 0x3333)]);
    assert_eq!(register::register_class(args), ATOM);
    registered(|class| {
        assert_eq!(class.name, vec![NAME]);
        assert_eq!(class.wndproc, WNDPROC);
        assert_eq!(class.style, 0x83);
        assert_eq!(class.cb_cls_extra, 16);
        assert_eq!(class.cb_wnd_extra, 20);
        assert_eq!(class.module, 0x1_4000_0000);
        assert_eq!(class.icon, 0x2222);
        assert_eq!(class.icon_sm, 0x3333);
        assert_eq!(class.cursor, 0x1111);
        assert_eq!(class.background, 6);
        assert!(!class.builtin);
    });
}

#[test]
fn a_class_registered_with_none_of_them_carries_none() {
    // Positive control for the field test above: with the structure cleared,
    // every one of those fields must come back zero.
    let args = armed(&[]);
    assert_eq!(register::register_class(args), ATOM);
    registered(|class| {
        assert_eq!((class.cb_cls_extra, class.cb_wnd_extra), (0, 0));
        assert_eq!((class.icon, class.icon_sm, class.cursor, class.module, class.background), (0, 0, 0, 0, 0));
    });
}

#[test]
fn the_icons_never_trade_places() {
    let args = armed(&[(abi::ICON, 0x2222)]);
    assert_eq!(register::register_class(args), ATOM);
    registered(|class| { assert_eq!(class.icon, 0x2222); assert_eq!(class.icon_sm, 0); });
    let args = armed(&[(abi::ICON_SM, 0x3333)]);
    assert_eq!(register::register_class(args), ATOM);
    registered(|class| { assert_eq!(class.icon, 0); assert_eq!(class.icon_sm, 0x3333); });
}

#[test]
fn a_builtin_registration_says_so() {
    let mut args = armed(&[]); args.a4 = 7;
    assert_eq!(register::register_class(args), ATOM);
    assert!(registered(|class| class.builtin));
}

#[test]
fn the_ansi_flag_selects_the_procedure_encoding() {
    for (flag, unicode) in [(0, true), (1, false), (0x7fa6_0000_0000, true), (0x7fa6_0000_0001, false)] {
        let mut args = armed(&[]); args.a5 = flag;
        assert_eq!(register::register_class(args), ATOM);
        assert_eq!(registered(|class| class.unicode), unicode);
    }
}

#[test]
fn the_client_menu_name_handle_travels_beside_the_structure() {
    let mut args = armed(&[]); args.a3 = MENU_RECORD;
    assert_eq!(register::register_class(args), ATOM);
    registered(|class| assert_eq!(class.menu_name, MENU_RECORD));
    // Positive control: no handle means no menu name.
    let args = armed(&[]);
    assert_eq!(register::register_class(args), ATOM);
    registered(|class| assert_eq!(class.menu_name, 0));
}

/// A class whose menu is named by resource id hands over MAKEINTRESOURCE: a
/// value below 0x10000 that addresses nothing. Reading through it registers no
/// menu name, and a window of that class then shows no menu bar.
#[test]
fn an_integer_resource_menu_name_survives_registration_unread() {
    let mut args = armed(&[]); args.a3 = INT_RESOURCE_MENU;
    // Nothing in the address space answers for this value, and the harness has
    // no reader for it: an entry that consulted it could only report zero.
    assert_eq!(register::register_class(args), ATOM);
    registered(|class| assert_eq!(class.menu_name, INT_RESOURCE_MENU));
}

#[test]
fn a_structure_whose_size_disagrees_is_not_registered() {
    let args = armed(&[]);
    STATE.with(|s| s.borrow_mut().size = abi::BYTES as u32 - 8);
    assert_eq!(register::register_class(args), 0);
    STATE.with(|s| assert!(s.borrow().registered.is_none()));
}

#[test]
fn an_unreadable_structure_or_name_registers_nothing() {
    let args = armed(&[]);
    STATE.with(|s| s.borrow_mut().faults = true);
    assert_eq!(register::register_class(args), 0);
    STATE.with(|s| assert!(s.borrow().registered.is_none()));
    let mut args = armed(&[]); args.a1 = NAME_POINTER + 8;
    assert_eq!(register::register_class(args), 0);
    STATE.with(|s| assert!(s.borrow().registered.is_none()));
    let mut args = armed(&[]); args.a0 = 0;
    assert_eq!(register::register_class(args), 0);
    STATE.with(|s| assert!(s.borrow().registered.is_none()));
}
