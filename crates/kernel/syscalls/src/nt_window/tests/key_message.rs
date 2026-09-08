//! The system-key decision, checked transition by transition against the
//! behaviour a running Win32 application observes.
use super::*;

const VK_A: u8 = 0x41;
const VK_F: u8 = 0x46;

fn down(latch: &mut SysKeyLatch, vk: u8) -> KeyDecision { latch.key(vk, true) }
fn up(latch: &mut SysKeyLatch, vk: u8) -> KeyDecision { latch.key(vk, false) }

#[test]
fn alt_alone_is_a_system_key_on_both_transitions() {
    let mut latch = SysKeyLatch::default();
    // The Alt press itself is a system key and already carries the context bit.
    assert_eq!(down(&mut latch, VK_LMENU), KeyDecision { message: WM_SYSKEYDOWN, alt_context: true });
    // Its release is a system key too, and the context bit is gone with it.
    assert_eq!(up(&mut latch, VK_LMENU), KeyDecision { message: WM_SYSKEYUP, alt_context: false });
    assert_eq!(down(&mut latch, VK_RMENU), KeyDecision { message: WM_SYSKEYDOWN, alt_context: true });
    assert_eq!(up(&mut latch, VK_RMENU), KeyDecision { message: WM_SYSKEYUP, alt_context: false });
}

#[test]
fn alt_letter_is_a_system_key_and_breaks_the_bare_alt_latch() {
    let mut latch = SysKeyLatch::default();
    assert_eq!(down(&mut latch, VK_LMENU).message, WM_SYSKEYDOWN);
    assert_eq!(down(&mut latch, VK_F), KeyDecision { message: WM_SYSKEYDOWN, alt_context: true });
    assert_eq!(up(&mut latch, VK_F), KeyDecision { message: WM_SYSKEYUP, alt_context: true });
    // The Alt release no longer opens a menu: another key came in between.
    assert_eq!(up(&mut latch, VK_LMENU), KeyDecision { message: WM_KEYUP, alt_context: false });
}

#[test]
fn a_second_alt_press_without_a_release_re_arms_nothing_new() {
    let mut latch = SysKeyLatch::default();
    assert_eq!(down(&mut latch, VK_LMENU).message, WM_SYSKEYDOWN);
    assert_eq!(down(&mut latch, VK_LMENU).message, WM_SYSKEYDOWN);
    assert_eq!(up(&mut latch, VK_LMENU).message, WM_SYSKEYUP);
}

#[test]
fn control_suppresses_the_system_form() {
    let mut latch = SysKeyLatch::default();
    assert_eq!(down(&mut latch, VK_LCONTROL), KeyDecision { message: WM_KEYDOWN, alt_context: false });
    // Alt pressed while Control is held is the layout's level-three modifier.
    assert_eq!(down(&mut latch, VK_RMENU), KeyDecision { message: WM_KEYDOWN, alt_context: true });
    assert_eq!(down(&mut latch, VK_A), KeyDecision { message: WM_KEYDOWN, alt_context: true });
    // Releasing Control while Alt is still down is a system key release.
    assert_eq!(up(&mut latch, VK_LCONTROL), KeyDecision { message: WM_SYSKEYUP, alt_context: true });
}

#[test]
fn an_ordinary_shortcut_stays_an_ordinary_key() {
    let mut latch = SysKeyLatch::default();
    assert_eq!(down(&mut latch, VK_LCONTROL).message, WM_KEYDOWN);
    assert_eq!(down(&mut latch, 0x4f), KeyDecision { message: WM_KEYDOWN, alt_context: false });
    assert_eq!(up(&mut latch, 0x4f).message, WM_KEYUP);
    assert_eq!(up(&mut latch, VK_LCONTROL).message, WM_KEYUP);
}

#[test]
fn f10_is_a_system_key_with_no_modifier_at_all() {
    let mut latch = SysKeyLatch::default();
    assert_eq!(down(&mut latch, VK_F10), KeyDecision { message: WM_SYSKEYDOWN, alt_context: false });
    assert_eq!(up(&mut latch, VK_F10), KeyDecision { message: WM_SYSKEYUP, alt_context: false });
}

#[test]
fn a_plain_key_is_never_a_system_key() {
    let mut latch = SysKeyLatch::default();
    assert_eq!(down(&mut latch, VK_A), KeyDecision { message: WM_KEYDOWN, alt_context: false });
    assert_eq!(up(&mut latch, VK_A), KeyDecision { message: WM_KEYUP, alt_context: false });
}

#[test]
fn one_alt_side_released_leaves_the_other_holding_the_context() {
    let mut latch = SysKeyLatch::default();
    assert!(down(&mut latch, VK_LMENU).alt_context);
    assert!(down(&mut latch, VK_RMENU).alt_context);
    assert!(up(&mut latch, VK_LMENU).alt_context);
    assert!(!up(&mut latch, VK_RMENU).alt_context);
}

#[test]
fn text_after_a_system_key_down_is_a_system_character() {
    let mut latch = SysKeyLatch::default();
    let alt = down(&mut latch, VK_LMENU);
    latch.note_key_message(alt.message, 0x2038_0001);
    let f = down(&mut latch, VK_F);
    latch.note_key_message(f.message, 0x2021_0001);
    assert_eq!(latch.char_message(), (WM_SYSCHAR, 0x2021_0001));
    // The key context is consumed: text with none before it is ordinary.
    assert_eq!(latch.char_message(), (WM_CHAR, 1));
}

#[test]
fn text_after_an_ordinary_key_down_is_an_ordinary_character() {
    let mut latch = SysKeyLatch::default();
    let a = down(&mut latch, VK_A);
    latch.note_key_message(a.message, 0x001e_0001);
    assert_eq!(latch.char_message(), (WM_CHAR, 0x001e_0001));
}

#[test]
fn a_key_release_leaves_no_character_context_behind() {
    let mut latch = SysKeyLatch::default();
    let a = down(&mut latch, VK_A);
    latch.note_key_message(a.message, 0x001e_0001);
    let release = up(&mut latch, VK_A);
    latch.note_key_message(release.message, 0xc01e_0001u32 as i32 as i64);
    assert_eq!(latch.char_message(), (WM_CHAR, 1));
}

#[test]
fn the_context_bit_is_the_bit_the_default_procedure_reads() {
    let mut latch = SysKeyLatch::default();
    let alt = down(&mut latch, VK_LMENU);
    assert_ne!(u32::from(alt.alt_context) << 29, 0);
    assert_eq!(KEY_ALT, 0x2000_0000);
}
