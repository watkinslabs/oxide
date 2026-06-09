// Core ioctl decode tests. The behavioral round-trips live in
// `core/tests.rs` against a real `TtyStruct`; here we pin the typed
// request constants to the Linux `_IO*` values so a transcription slip
// (off-by-one vs `016_ioctl.rs`) is caught at unit-test time.
use super::req;

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
    assert_eq!(req::TIOCNOTTY, 0x5422);
    assert_eq!(req::TIOCGSID, 0x5429);
}
