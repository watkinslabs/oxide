use super::*;
    use proptest::prelude::*;

    // host glibc oracle (the `libc` crate doesn't re-export these); the test
    // binary links the system libc so the externs resolve.
    extern "C" {
        fn inet_pton(af: i32, src: *const u8, dst: *mut u8) -> i32;
        fn inet_ntop(af: i32, src: *const u8, dst: *mut u8, size: u32) -> *const u8;
    }

    fn host_pton(af: i32, s: &str) -> Option<std::vec::Vec<u8>> {
        let c = std::ffi::CString::new(s).unwrap();
        let n = if af == AF_INET { 4 } else { 16 };
        let mut buf = std::vec![0u8; n];
        // SAFETY: c is NUL-terminated; buf holds n bytes for the family.
        let r = unsafe { inet_pton(af, c.as_ptr() as *const u8, buf.as_mut_ptr()) };
        if r == 1 { Some(buf) } else { None }
    }
    fn host_ntop(af: i32, bytes: &[u8]) -> Option<std::string::String> {
        let mut buf = std::vec![0u8; 64];
        // SAFETY: bytes has the right length for af; buf is 64 bytes.
        let p = unsafe { inet_ntop(af, bytes.as_ptr(), buf.as_mut_ptr(), 64) };
        if p.is_null() { return None; }
        let end = buf.iter().position(|&b| b == 0).unwrap();
        Some(std::string::String::from_utf8(buf[..end].to_vec()).unwrap())
    }

    proptest! {
        #[test]
        fn pton4_matches_host(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
            let s = std::format!("{a}.{b}.{c}.{d}");
            let mut o = [0u8; 4];
            prop_assert!(pton4(s.as_bytes(), &mut o));
            prop_assert_eq!(&o[..], &host_pton(AF_INET, &s).unwrap()[..]);
        }
        #[test]
        fn ntop4_matches_host(bytes in any::<[u8; 4]>()) {
            let mut o = [0u8; 16];
            let n = ntop4(&bytes, &mut o).unwrap();
            prop_assert_eq!(std::str::from_utf8(&o[..n]).unwrap(), host_ntop(AF_INET, &bytes).unwrap());
        }
        #[test]
        fn v6_roundtrip_matches_host(g in any::<[u16; 8]>()) {
            let mut bytes = [0u8; 16];
            for k in 0..8 { bytes[k*2..k*2+2].copy_from_slice(&g[k].to_be_bytes()); }
            // our ntop6 must equal host inet_ntop
            let mut o = [0u8; 46];
            let n = ntop6(&bytes, &mut o).unwrap();
            let ours = std::str::from_utf8(&o[..n]).unwrap();
            prop_assert_eq!(ours, host_ntop(AF_INET6, &bytes).unwrap());
            // and our pton6 of the host string must reproduce the bytes
            let hs = host_ntop(AF_INET6, &bytes).unwrap();
            let mut back = [0u8; 16];
            prop_assert!(pton6(hs.as_bytes(), &mut back));
            prop_assert_eq!(&back[..], &bytes[..]);
        }
    }

    #[test]
    fn pton_rejects_bad() {
        let mut o4 = [0u8; 4];
        assert!(!pton4(b"1.2.3", &mut o4));
        assert!(!pton4(b"1.2.3.256", &mut o4));
        assert!(!pton4(b"1.2.3.04", &mut o4)); // leading zero
        assert!(!pton4(b"1.2.3.4.5", &mut o4));
        let mut o6 = [0u8; 16];
        assert!(pton6(b"::1", &mut o6));
        assert_eq!(o6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(pton6(b"2001:db8::1", &mut o6));
        assert!(!pton6(b"1::2::3", &mut o6)); // two ::
    }
