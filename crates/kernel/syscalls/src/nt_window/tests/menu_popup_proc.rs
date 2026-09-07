use super::*;

#[test]
fn the_popup_class_answers_the_messages_that_carry_its_menu() {
    assert_eq!(popup_proc_action(0x0001, 0), PopupProcAction::StoreMenu);
    assert_eq!(popup_proc_action(MN_GETHMENU, 0), PopupProcAction::ReportMenu);
    assert_eq!(popup_proc_action(0x0018, 1), PopupProcAction::Shown(true));
    assert_eq!(popup_proc_action(0x0018, 0), PopupProcAction::Shown(false));
    assert_eq!(popup_proc_action(0x0002, 0), PopupProcAction::Destroyed);
}

#[test]
fn a_popup_menu_never_takes_activation_and_erases_itself() {
    assert_eq!(popup_proc_action(0x0021, 0), PopupProcAction::NoActivate);
    assert_eq!(popup_proc_action(0x0014, 0), PopupProcAction::EraseHandled);
    assert_eq!((MA_NOACTIVATE, ERASE_HANDLED), (3, 1));
}

#[test]
fn both_paint_requests_draw_the_same_menu() {
    assert_eq!(popup_proc_action(0x000f, 0), PopupProcAction::Paint);
    assert_eq!(popup_proc_action(0x0318, 0), PopupProcAction::PrintClient);
}

#[test]
fn every_other_message_is_the_default_procedures() {
    for message in [0x0005u32, 0x0020, 0x0111, 0x0200] {
        assert_eq!(popup_proc_action(message, 0), PopupProcAction::Default);
    }
}
