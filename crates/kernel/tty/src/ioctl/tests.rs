// Core ioctl decode tests. The behavioral round-trips live in
// `core/tests.rs` against a real `TtyStruct`; here we pin the typed
// request constants to the Linux `_IO*` values so a transcription slip
// (off-by-one vs `016_ioctl.rs`) is caught at unit-test time.
use super::{modem, req};

#[test]
fn modem_line_bits_match_the_single_linux_uapi_owner() {
    assert_eq!([modem::TIOCM_LE, modem::TIOCM_DTR, modem::TIOCM_RTS, modem::TIOCM_ST,
                modem::TIOCM_SR, modem::TIOCM_CTS, modem::TIOCM_CAR, modem::TIOCM_RNG,
                modem::TIOCM_DSR, modem::TIOCM_OUT1, modem::TIOCM_OUT2, modem::TIOCM_LOOP],
               [0x001, 0x002, 0x004, 0x008, 0x010, 0x020,
                0x040, 0x080, 0x100, 0x2000, 0x4000, 0x8000]);
    assert_eq!((modem::TIOCM_CD, modem::TIOCM_RI), (modem::TIOCM_CAR, modem::TIOCM_RNG));
}

#[test]
fn request_numbers_match_linux_uapi() {
    assert_eq!(req::TCGETS, 0x5401);
    assert_eq!(req::TCSETS, 0x5402);
    assert_eq!(req::TCSETSW, 0x5403);
    assert_eq!(req::TCSETSF, 0x5404);
    assert_eq!(req::TIOCSCTTY, 0x540E);
    assert_eq!(req::TIOCGPGRP, 0x540F);
    assert_eq!(req::TIOCSPGRP, 0x5410);
    assert_eq!(req::TIOCGWINSZ, 0x5413);
    assert_eq!(req::TIOCSWINSZ, 0x5414);
    assert_eq!(req::TIOCGEXCL, 0x80045440);
    assert_eq!(req::TIOCNOTTY, 0x5422);
    assert_eq!(req::TIOCGSID, 0x5429);
}
