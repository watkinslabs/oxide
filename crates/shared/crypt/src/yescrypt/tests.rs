// Differential test vectors generated against the HOST's real libxcrypt
// (crypt_r via ctypes) on this dev machine — NOT hand-written. See
// scratch/ generation script referenced in the F723-yescrypt PR description.
use super::hash;

struct Vector { pw: &'static [u8], setting: &'static str, want: &'static str }

const VECTORS: &[Vector] = &[
    Vector { pw: b"", setting: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.$wcXdyp3qHg3mW/WAQtjaYAdxT5VnTZZlgnp7uwY8x0C" },
    Vector { pw: b"\x61", setting: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.$3iVBLCemOdgAF0/XDH/86cLSbS4tXGz1GlhMpjyZkxC" },
    Vector { pw: b"\x68\x65\x6c\x6c\x6f", setting: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.$78j9btt4ZZOkP6C0/QaMn/WTZj//N6aZzBJtsb7VoO3" },
    Vector { pw: b"\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21", setting: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.$UCJMVjBxeWjpsan0M0hnoYNnqy0bMNHC0rvmxzHobnD" },
    Vector { pw: b"\x73\x77\x6f\x72\x64\x66\x69\x73\x68", setting: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.$LCe1JCix6bI1FBRHYYe1HbpX0bKLzeVM/wQ0CQpGrA1" },
    Vector { pw: b"\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78", setting: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.$PZO9H7BIW9P5waLxArE8b9UevaetqQc1j7Krp6KyB6." },
    Vector { pw: b"\x75\x6e\x69\x63\x6f\x64\x65\x65\x2d\x75\x74\x66\x38\x2d\x62\x79\x74\x65\x73", setting: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.$WiqsB5HY3IJ2kYlXxWvslGb8XQh8E9MNf4ZCPDKO0k." },
    Vector { pw: b"\x70\x40\x73\x73\x20\x77\x30\x72\x64\x21\x23\x24\x25", setting: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j75$.2U.1EE/4Q.07ck0AoU1D.$WJrj7HUrw6n3o8Hybi7Si1hU.0drJIZK4QIbe09H290" },
    Vector { pw: b"", setting: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.$jF/Xlz2ql0uaH1sZiCQF50MULf.zaZaROgIpX1pW2I8" },
    Vector { pw: b"\x61", setting: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.$e4TxbpObeYfA5XJFbEF/QsZMr1lrb0Gtb/YxbgWs5A7" },
    Vector { pw: b"\x68\x65\x6c\x6c\x6f", setting: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.$ho/uNeLKHmufc1ajHTavL9oov./cbEAuIZkiG4Vit4." },
    Vector { pw: b"\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21", setting: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.$Odcd1beQJn5TVU1FlTzhWB1CGdNqmC0LS/kXU.Wxgf/" },
    Vector { pw: b"\x73\x77\x6f\x72\x64\x66\x69\x73\x68", setting: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.$J.XCGfzN5gMAF9tG6ZEYDA0jRHEJuEw25mdEXoJq/Q0" },
    Vector { pw: b"\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78\x78", setting: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.$UUbo5u4NvOIY4x72XL24v1ZR6RziApq08XbgLZSObTA" },
    Vector { pw: b"\x75\x6e\x69\x63\x6f\x64\x65\x65\x2d\x75\x74\x66\x38\x2d\x62\x79\x74\x65\x73", setting: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.$kmvlWffhhzes6xpBb01RShCOn3.memnXEMSytqakSJD" },
    Vector { pw: b"\x70\x40\x73\x73\x20\x77\x30\x72\x64\x21\x23\x24\x25", setting: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j85$.2U.1EE/4Q.07ck0AoU1D.$4CZ7hLk8yqFlEItyLtiBejS7Mf.3faSkUnQnzXcXTM4" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$.oU4bEHECh3Op7sXQaeh11", want: "$y$j75$.oU4bEHECh3Op7sXQaeh11$SXg/FTC949J4EF5sZLMAKqlomR8mHGc1ENPWDbB0dB3" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$5EF6ig1GJ7qPwZcZX0Pj81", want: "$y$j75$5EF6ig1GJ7qPwZcZX0Pj81$64wFVlK2X9Nf99OJyVeOYLMg0o.ujHIBsa8NQkWOdHC" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$Cg/8p6oHQZaR10NbeS9lF1", want: "$y$j75$Cg/8p6oHQZaR10NbeS9lF1$7JM6oRTaucRYmYYWQwHf64jzec/1gei4w3WfAVCgZi2" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$J6m9wYYJX/LT8S7dluvmM1", want: "$y$j75$J6m9wYYJX/LT8S7dluvmM1$17X9Co5N/G6hTr0RiCT4k2JFBkdrYn3b85d87dr7jj8" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$QYWB1/JLeR5VFutesKgoT1", want: "$y$j75$QYWB1/JLeR5VFutesKgoT1$fKuLkf//xlOhh9eKns/Kzt7791Y1isW1EkKEGqdyRe9" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$X.HD8R3NltrWMKegzmQqa1", want: "$y$j75$X.HD8R3NltrWMKegzmQqa1$.buXUYU9jbTHKwQp1GJbSe2gkmni7GCXtI5p4PCFEe3" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$EAV3Nkl5WI08fsGAoQXCx.", want: "$y$j75$EAV3Nkl5WI08fsGAoQXCx.$OVYP..H07VYJX2STOphkcAgak2a/ykHMYfVX.bPGt09" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$MgV5VEm7eo0AnMHCwwXE3VoGC33JLdJL", want: "$y$j75$MgV5VEm7eo0AnMHCwwXE3VoGC33JLdJL$Fdz2PmPaxWHfWqgIkZvIYnwOGTgeTmTHqVNcrSOTxXD" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$UAW7dkm9mI1CvsHE2RYGB/pIKZ3LT7KNchaPlFrRup5", want: "$y$j75$UAW7dkm9mI1CvsHE2RYGB/pIKZ3LT7KNchaPlFrRup5$IKkMfDBJgf/uL4YVSP9Vj37kl3/qGNurEBSknBZpua1" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$kAXBtknD0J2G9tIIIRZKR/qMaZ4Pj7LRshbT/GsV8q6YHONaQydcZWuei49hrePj", want: "$y$j75$kAXBtknD0J2G9tIIIRZKR/qMaZ4Pj7LRshbT/GsV8q6YHONaQydcZWuei49hrePj$k2S64Axc4b/vorUNWPH6ELNT7QVIgYO.JMfGGIX7neC" },
    Vector { pw: b"\x74\x65\x73\x74\x70\x77\x31\x32\x33", setting: "$y$j75$.BYF7loHGJ3KPtJMYRaOh/rQqZ5Tz7MV6icXFGtZOq7cXOOegyegpWviy4Al5fQnEDhpNnxrWLCufvSwoTjyx1", want: "$y$j75$.BYF7loHGJ3KPtJMYRaOh/rQqZ5Tz7MV6icXFGtZOq7cXOOegyegpWviy4Al5fQnEDhpNnxrWLCufvSwoTjyx1$H4ophMZXVq/JSir4mDe8Ovw8J8GcLqttZ6aD89qz6Z2" },
    Vector { pw: b"\x68\x65\x6c\x6c\x6f", setting: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.$8llHWBnsUT/C.MKNI.bcvn4rWKZJ05dBRCYGXbZsYQ6" },
    Vector { pw: b"", setting: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.$SmJZIbjHRp4Z4W4wxy1fs7FwUQaU7p33Xm6oOyuYI22" },
    Vector { pw: b"\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21", setting: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.$4NfHmls6n5rZm/6tJwI055XCiV/4XUeUm79Q8K9xWx2" },
    Vector { pw: b"\x73\x77\x6f\x72\x64\x66\x69\x73\x68", setting: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.$vssF9Mc9.8BXPtXVCTCcoga1vWxeOcTOP5giRFilSC/" },
    Vector { pw: b"\x62\x69\x67\x6e\x68\x61\x73\x68", setting: "$y$jAT$.2U.1EE/4Q.07ck0AoU1D.", want: "$y$jAT$.2U.1EE/4Q.07ck0AoU1D.$2HYNr/A8jzTfMOg249.buajVcAP79IhDZvWs9lCh.m9" },
    Vector { pw: b"\x72\x6f\x75\x6e\x64\x74\x72\x69\x70", setting: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.$vJcIwDZbLx8GfKyILukIsZpwoT/noIH5ObfNYgDvdn6", want: "$y$j9T$.2U.1EE/4Q.07ck0AoU1D.$vJcIwDZbLx8GfKyILukIsZpwoT/noIH5ObfNYgDvdn6" },
    Vector { pw: b"\x68\x75\x6e\x74\x65\x72\x32", setting: "$y$j9T$EgqTpNAyG3jlPEdCgLJPY.", want: "$y$j9T$EgqTpNAyG3jlPEdCgLJPY.$66PoBixZabZBxJyBL1G6Ef7UveIW0L.FltydbCH1D.7" },
    Vector { pw: b"", setting: "$y$j9T$EgqTpNAyG3jlPEdCgLJPY.", want: "$y$j9T$EgqTpNAyG3jlPEdCgLJPY.$hwCxTx1FTLlghLmTd/mRuODNL5yZU.erY8g.jFzLolC" },
    Vector { pw: b"\x6f\x78\x69\x64\x65", setting: "$y$j9T$EgqTpNAyG3jlPEdCgLJPY.", want: "$y$j9T$EgqTpNAyG3jlPEdCgLJPY.$xirFzF.1sAbwW/OPN7mKabJMdcj/jv.CIuDy.qP6cV2" },
    Vector { pw: b"\x68\x75\x6e\x74\x65\x72\x32", setting: "$y$j9T$7nufRRDsGwv3J9mgBko4/1", want: "$y$j9T$7nufRRDsGwv3J9mgBko4/1$TpWwiBJwQ.924zEIxaU1nDtVJ0pxuYvprG0PEE/PgM5" },
    Vector { pw: b"", setting: "$y$j9T$7nufRRDsGwv3J9mgBko4/1", want: "$y$j9T$7nufRRDsGwv3J9mgBko4/1$0YKaFiWP1WGiIM6zXMffAvKuZQ9TyYQP2Vy.pZYo/l6" },
    Vector { pw: b"\x6f\x78\x69\x64\x65", setting: "$y$j9T$7nufRRDsGwv3J9mgBko4/1", want: "$y$j9T$7nufRRDsGwv3J9mgBko4/1$mMYAJuf8p8eR0l7UfW3zAuGX7ZtQL2e8sy0i7WtCbJB" },
];

#[test]
fn oracle_vectors_match_byte_for_byte() {
    for v in VECTORS {
        let got = hash(v.pw, v.setting.as_bytes());
        assert_eq!(got.as_deref(), Some(v.want), "pw={:?} setting={}", v.pw, v.setting);
    }
}

#[test]
fn malformed_settings_rejected() {
    assert!(hash(b"x", b"$y$").is_none());              // no fields at all
    assert!(hash(b"x", b"$y$j9T").is_none());            // missing trailing '$' after fields
    assert!(hash(b"x", b"plain").is_none());             // not even $y$
    assert!(hash(b"x", b"$y$!!!$salt").is_none());       // invalid field b64
    assert!(hash(b"x", b"$y$j9T$!!!!").is_none());       // invalid salt b64 (only invalid chars)
    assert!(hash(b"x", b"$6$saltstring").is_none());     // sha512crypt id, not ours to parse here
}

#[test]
fn unsupported_parameter_combinations_rejected() {
    use super::params::{parse_fields, YescryptParams};
    // p != 1 is parseable (field syntax supports it) but must be reported
    // Unsupported by the KDF layer, never silently mis-computed.
    let params = YescryptParams { flags: super::params::YESCRYPT_RW_DEFAULTS, n: 4096, r: 8, p: 2, t: 0, g: 0, nrom: 0 };
    assert!(super::kdf::yescrypt_kdf(b"x", b"salt", &params).is_none());

    // g != 0 (hash upgrade) is explicitly unimplemented upstream too.
    let params_g = YescryptParams { g: 1, ..params.clone() };
    assert!(super::kdf::yescrypt_kdf(b"x", b"salt", &params_g).is_none());

    // NROM != 0 (ROM) — no ROM support.
    let params_rom = YescryptParams { p: 1, nrom: 1024, ..params };
    assert!(super::kdf::yescrypt_kdf(b"x", b"salt", &params_rom).is_none());

    let _ = parse_fields(b"j9T$"); // exercised elsewhere; keep import used
}

#[test]
fn wrong_password_mismatches() {
    // Same salt/params as a real vector above, different (wrong) password:
    // must NOT match the real hash.
    let got = hash(b"definitely-not-the-password", "$y$j9T$EgqTpNAyG3jlPEdCgLJPY.".as_bytes());
    assert_ne!(got.as_deref(), Some("$y$j9T$EgqTpNAyG3jlPEdCgLJPY.$xirFzF.1sAbwW/OPN7mKabJMdcj/jv.CIuDy.qP6cV2"));
}

#[test]
fn gensalt_roundtrips_through_hash() {
    let rb: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(17));
    let setting = super::gensalt(1, &rb).unwrap();
    let h1 = hash(b"roundtrip-pw", setting.as_bytes()).unwrap();
    let h2 = hash(b"roundtrip-pw", h1.as_bytes()).unwrap();
    assert_eq!(h1, h2);
    let wrong = hash(b"other-pw", setting.as_bytes()).unwrap();
    assert_ne!(wrong, h1);
}

// Hand-crafted setting strings exercising each `flavor` value ($y$'s field
// codec supports classic scrypt (0) and WORM (1) too, not just RW) at the
// smallest valid N/r, each checked against the host oracle. These isolated
// a real bug during development (yescrypt_kdf_body's C `passwd` pointer
// aliases its `sha256` scratch buffer, which gets mutated after the first
// PBKDF2 call and again by smix()'s RW S-box-seed HMAC step — see kdf.rs).

#[test]
fn classic_flavor_via_y_prefix() {
    let got = hash(b"hello", b"$y$.7.$saltsalt");
    assert_eq!(got.as_deref(), Some("$y$.7.$saltsalt$ta2POpiHKSJW3tsK0AcXq1rmblo7Kdq/xZCU4Vo7mf0"));
}

#[test]
fn worm_flavor() {
    let got = hash(b"hello", b"$y$/7.$saltsalt");
    assert_eq!(got.as_deref(), Some("$y$/7.$saltsalt$QKuQuPR8404M6Nz6viMHkwnphx/M6chUSyBcGfD4L67"));
}

#[test]
fn rw_flavor_minimal_n4_r1() {
    let got = hash(b"hello", b"$y$j/.$saltsalt");
    assert_eq!(got.as_deref(), Some("$y$j/.$saltsalt$ZhUgGylR3.Qv7WrqazvIbgSY4VA0Nm26FXunaO898/3"));
}
