use super::*;
    // #![no_std] crate: proptest's macros are not in the prelude either.
    // (No alloc imports here -- these tests use fixed buffers, unlike
    // stdio/fmt/tests.rs which genuinely needs Vec/String/format!.)
    use proptest::{prop_assert_eq, prop_assume, proptest};

    proptest! {
        #[test]
        fn roundtrip_matches_core(cp in 0u32..=0x10FFFF) {
            prop_assume!(char::from_u32(cp).is_some()); // skip surrogates
            let (bytes, len) = encode_utf8(cp);
            // matches Rust core's UTF-8 encoding
            let mut buf = [0u8; 4];
            let s = char::from_u32(cp).unwrap().encode_utf8(&mut buf);
            prop_assert_eq!(&bytes[..len], s.as_bytes());
            // decode round-trips
            prop_assert_eq!(decode_utf8(&bytes[..len]), Ok((cp, len)));
        }
    }

    #[test]
    fn known_vectors() {
        assert_eq!(decode_utf8(&[0xC3, 0xA9]), Ok((0xE9, 2))); // é
        assert_eq!(decode_utf8(&[0xE2, 0x82, 0xAC]), Ok((0x20AC, 3))); // €
        assert_eq!(decode_utf8(&[0xF0, 0x9D, 0x84, 0x9E]), Ok((0x1D11E, 4))); // 𝄞
        assert_eq!(decode_utf8(&[0x41]), Ok((0x41, 1)));
        assert_eq!(decode_utf8(&[0x00]), Ok((0, 1)));
        // rejections
        assert_eq!(decode_utf8(&[0xC0, 0x80]), Err(-1)); // overlong NUL
        assert_eq!(decode_utf8(&[0xED, 0xA0, 0x80]), Err(-1)); // surrogate
        assert_eq!(decode_utf8(&[0x80]), Err(-1)); // lone continuation
        assert_eq!(decode_utf8(&[0xE2, 0x82]), Err(-2)); // incomplete
        assert_eq!(decode_utf8(&[]), Err(-2));
    }
