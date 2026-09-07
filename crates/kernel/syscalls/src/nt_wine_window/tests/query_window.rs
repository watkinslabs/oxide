use super::*;

fn facts() -> Facts {
    Facts { pid: 0x11, thread_id: 0x22, active: 0x33, focus: 0x44, hung: true, foreground_thread: true,
        default_ime_window: 0x55, default_input_context: 0x66 }
}

#[test]
fn the_ordinal_is_the_one_the_client_library_imports() { assert_eq!(ORDINAL, 0x14df); }

#[test]
fn the_classes_keep_their_reference_order() {
    assert_eq!([WINDOW_PROCESS, WINDOW_PROCESS2, WINDOW_THREAD, WINDOW_ACTIVE_WINDOW, WINDOW_FOCUS_WINDOW, WINDOW_IS_HUNG,
        WINDOW_CLIENT_BASE, WINDOW_IS_FOREGROUND_THREAD, WINDOW_DEFAULT_IME_WINDOW, WINDOW_DEFAULT_INPUT_CONTEXT],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

#[test]
fn each_class_reads_its_own_fact() {
    let window = Some(facts());
    assert_eq!(answer(WINDOW_PROCESS, window), 0x11);
    assert_eq!(answer(WINDOW_PROCESS2, window), 0x11);
    assert_eq!(answer(WINDOW_THREAD, window), 0x22);
    assert_eq!(answer(WINDOW_ACTIVE_WINDOW, window), 0x33);
    assert_eq!(answer(WINDOW_FOCUS_WINDOW, window), 0x44);
    assert_eq!(answer(WINDOW_IS_HUNG, window), 1);
    assert_eq!(answer(WINDOW_IS_FOREGROUND_THREAD, window), 1);
    assert_eq!(answer(WINDOW_DEFAULT_IME_WINDOW, window), 0x55);
    assert_eq!(answer(WINDOW_DEFAULT_INPUT_CONTEXT, window), 0x66);
}

#[test]
fn the_two_boolean_classes_report_one_or_zero() {
    let mut quiet = facts();
    quiet.hung = false;
    quiet.foreground_thread = false;
    assert_eq!(answer(WINDOW_IS_HUNG, Some(quiet)), 0);
    assert_eq!(answer(WINDOW_IS_FOREGROUND_THREAD, Some(quiet)), 0);
}

#[test]
fn the_client_base_class_and_any_unnamed_class_answer_zero() {
    let window = Some(facts());
    assert_eq!(answer(WINDOW_CLIENT_BASE, window), 0);
    for cls in [10, 11, 0xffff, u64::MAX] { assert_eq!(answer(cls, window), 0, "class {cls}"); }
}

#[test]
fn an_unresolvable_window_answers_zero_for_every_class_that_reads_it() {
    for cls in [WINDOW_PROCESS, WINDOW_PROCESS2, WINDOW_THREAD, WINDOW_ACTIVE_WINDOW, WINDOW_FOCUS_WINDOW,
        WINDOW_IS_HUNG, WINDOW_CLIENT_BASE, WINDOW_IS_FOREGROUND_THREAD, WINDOW_DEFAULT_IME_WINDOW] {
        assert_eq!(answer(cls, None), 0, "class {cls}");
    }
}

#[test]
fn only_the_default_input_context_class_skips_the_window() {
    for cls in [WINDOW_PROCESS, WINDOW_PROCESS2, WINDOW_THREAD, WINDOW_ACTIVE_WINDOW, WINDOW_FOCUS_WINDOW,
        WINDOW_IS_HUNG, WINDOW_CLIENT_BASE, WINDOW_IS_FOREGROUND_THREAD, WINDOW_DEFAULT_IME_WINDOW, 10] {
        assert!(needs_window(cls), "class {cls}");
    }
    assert!(!needs_window(WINDOW_DEFAULT_INPUT_CONTEXT));
}
