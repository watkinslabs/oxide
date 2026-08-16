// Provenance: ALSA's snd_ctl_card_info / snd_pcm_info field widths and the
// NUL-padding userspace relies on when it prints a card name.

use super::*;

#[test]
fn identity_fields_truncate_to_the_alsa_widths() {
    let long = [b'x'; 200];
    let ident = CardIdentity::new(&long, &long, &long, &long, &long, &long, &long);
    assert_eq!(ident.id.len(), ID_WIDTH);
    assert_eq!(ident.name.len(), NAME_WIDTH);
    assert_eq!(ident.longname.len(), LONG_WIDTH);
    assert_eq!(ident.components.len(), COMPONENTS_WIDTH);
    assert!(ident.id.iter().all(|&b| b == b'x'));
}

#[test]
fn short_identity_fields_are_nul_padded_not_garbage() {
    let ident = CardIdentity::new(b"HDA", b"HDA Intel", b"HDA Intel PCH", b"HDA Intel PCH at 0xf000",
                                  b"Realtek ALC888", b"HDA:10ec0888", b"ALC888 Analog");
    assert_eq!(trim(&ident.id), b"HDA");
    assert_eq!(ident.id[3], 0);
    assert_eq!(trim(&ident.name), b"HDA Intel PCH");
    assert_eq!(trim(&ident.components), b"HDA:10ec0888");
}

#[test]
fn pcm_stream_name_appends_the_direction() {
    let ident = CardIdentity::new(b"HDA", b"HDA Intel", b"HDA", b"HDA", b"HDA", b"", b"ALC888 Analog");
    assert_eq!(trim(&pcm_stream_name(&ident, false)), b"ALC888 Analog Playback");
    assert_eq!(trim(&pcm_stream_name(&ident, true)), b"ALC888 Analog Capture");
}

#[test]
fn pcm_stream_name_truncates_rather_than_overflowing() {
    let stem = [b'z'; NAME_WIDTH];
    let ident = CardIdentity::new(b"", b"", b"", b"", b"", b"", &stem);
    let name = pcm_stream_name(&ident, false);
    assert_eq!(name.len(), LONG_WIDTH);
    assert_eq!(trim(&name).len(), NAME_WIDTH + b" Playback".len());
}
