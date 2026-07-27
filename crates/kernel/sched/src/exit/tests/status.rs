use crate::exit::status::*;
use crate::signum::{killed_status, Signum, WSTATUS_CORE, WSTATUS_SIGNALED};

// Userspace `<bits/waitstatus.h>` decoders, spelled out so the assertions read
// the way a C program observes the status word.
const fn wifexited(s: i32) -> bool { s & 0x7f == 0 }
const fn wexitstatus(s: i32) -> i32 { (s >> 8) & 0xff }
const fn wifsignaled(s: i32) -> bool { ((s & 0x7f) + 1) >> 1 > 0 }
const fn wtermsig(s: i32) -> i32 { s & 0x7f }
const fn wcoredump(s: i32) -> bool { s & 0x80 != 0 }

#[test]
fn normal_exit_encodes_code_in_the_high_byte() {
    for code in [0u64, 1, 42, 127, 255] {
        let internal = from_exit_code(code);
        let st = wait_status(internal);
        assert!(wifexited(st), "code {code}");
        assert!(!wifsignaled(st), "code {code}");
        assert_eq!(wexitstatus(st), code as i32, "code {code}");
    }
}

#[test]
fn exit_code_is_truncated_to_a_byte_like_linux() {
    // SYSCALL_DEFINE1(exit): `(error_code & 0xff) << 8`. 0x180 reports 0x80.
    assert_eq!(wexitstatus(wait_status(from_exit_code(0x180))), 0x80);
    assert_eq!(wexitstatus(wait_status(from_exit_code(0x100))), 0);
    assert_eq!(wexitstatus(wait_status(from_exit_code(u64::MAX))), 0xff);
    // and never collides with the killed-by-signal marker
    for code in 0u64..=0x3ff {
        assert!(!is_signaled(from_exit_code(code)), "code {code}");
    }
}

#[test]
fn signal_death_encodes_signo_and_never_looks_exited() {
    let internal = killed_status(Signum::Sigterm as u32);
    let st = wait_status(internal);
    assert!(wifsignaled(st));
    assert!(!wifexited(st));
    assert_eq!(wtermsig(st), Signum::Sigterm as i32);
    assert!(!wcoredump(st));
}

#[test]
fn core_dumping_signal_keeps_the_wcoredump_bit_through_wait() {
    // The pre-fix wait4/waitid encoder masked with 0x7f and dropped this bit,
    // so bash never printed "(core dumped)".
    for sig in [Signum::Sigsegv, Signum::Sigabrt, Signum::Sigquit, Signum::Sigbus] {
        let internal = killed_status(sig as u32);
        assert_ne!(internal & WSTATUS_CORE, 0, "{sig:?}");
        let st = wait_status(internal);
        assert!(wifsignaled(st), "{sig:?}");
        assert_eq!(wtermsig(st), sig as i32, "{sig:?}");
        assert!(wcoredump(st), "{sig:?}");
    }
}

#[test]
fn internal_accessors_agree_with_the_userspace_macros() {
    let exited = from_exit_code(7);
    assert!(!is_signaled(exited));
    assert_eq!(exit_code(exited), 7);
    assert_eq!(term_sig(exited), 0);
    assert!(!core_dumped(exited));

    let dumped = killed_status(Signum::Sigsegv as u32);
    assert!(is_signaled(dumped));
    assert_eq!(term_sig(dumped), Signum::Sigsegv as i32);
    assert!(core_dumped(dumped));
    assert_eq!(exit_code(dumped), 0);
    assert_ne!(dumped & WSTATUS_SIGNALED, 0);
}

#[test]
fn stopped_and_continued_match_the_wait4_encodings() {
    let st = stopped_status(Signum::Sigtstp as i32);
    assert!(!wifexited(st));
    assert_eq!(st & 0xff, 0x7f);
    assert_eq!((st >> 8) & 0xff, Signum::Sigtstp as i32);
    assert_eq!(continued_status(), 0xffff);
}
