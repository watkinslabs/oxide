use super::*;
    // `glibc` is #![no_std]: Vec/String/format! are not in the prelude, so
    // the test module must name them explicitly. Without these the whole
    // module fails to compile, which `cargo test --workspace` was hiding
    // behind 111 vendored-crate errors until C225 excluded vendor/.
    extern crate alloc;
    use alloc::{format, string::String, vec, vec::Vec};

    struct VecSink { v: Vec<u8>, total: usize }
    impl Sink for VecSink { fn push(&mut self, b: u8) { self.v.push(b); self.total += 1; } fn count(&self) -> usize { self.total } }

    enum A { I32(i32), U32(u32) }
    struct TestArgs { items: Vec<A>, i: usize }
    impl Args for TestArgs {
        unsafe fn next_i32(&mut self) -> i32 { let r = match self.items[self.i] { A::I32(x) => x, _ => panic!() }; self.i += 1; r }
        unsafe fn next_u32(&mut self) -> u32 { let r = match self.items[self.i] { A::U32(x) => x, _ => panic!() }; self.i += 1; r }
        unsafe fn next_i64(&mut self) -> i64 { 0 }
        unsafe fn next_u64(&mut self) -> u64 { 0 }
        unsafe fn next_ptr(&mut self) -> *const u8 { core::ptr::null() }
        unsafe fn next_f64(&mut self) -> f64 { 0.0 }
    }

    fn host(fmt: &str, signed: bool, v: i64) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let cf = format!("{fmt}\0");
        // SAFETY: cf is NUL-terminated; buf is 256 bytes; one int vararg matches `fmt`.
        let n = unsafe {
            if signed { libc::snprintf(buf.as_mut_ptr() as *mut _, 256, cf.as_ptr() as *const _, v as i32) }
            else { libc::snprintf(buf.as_mut_ptr() as *mut _, 256, cf.as_ptr() as *const _, v as u32) }
        };
        buf[..n as usize].to_vec()
    }

    fn ours(fmt: &str, arg: A) -> Vec<u8> {
        let cf = format!("{fmt}\0");
        let mut sink = VecSink { v: Vec::new(), total: 0 };
        let mut args = TestArgs { items: vec![arg], i: 0 };
        // SAFETY: cf is NUL-terminated; args supplies exactly one matching vararg.
        unsafe { vformat(&mut sink, cf.as_ptr(), &mut args); }
        sink.v
    }

    use proptest::prelude::*;
    fn flagset() -> impl Strategy<Value = String> {
        proptest::collection::vec(prop_oneof![Just('-'), Just('+'), Just(' '), Just('#'), Just('0')], 0..3)
            .prop_map(|cs| cs.into_iter().collect())
    }
    proptest! {
        #[test]
        fn signed_dec_matches(flags in flagset(), width in 0usize..14, prec in prop::option::of(0usize..8), v in any::<i32>()) {
            let p = prec.map(|x| format!(".{x}")).unwrap_or_default();
            let fmt = format!("%{flags}{width}{p}d");
            prop_assert_eq!(ours(&fmt, A::I32(v)), host(&fmt, true, v as i64), "fmt={}", fmt);
        }
        #[test]
        fn unsigned_hex_matches(flags in flagset(), width in 0usize..14, prec in prop::option::of(0usize..8), v in any::<u32>(), upper in any::<bool>()) {
            let p = prec.map(|x| format!(".{x}")).unwrap_or_default();
            let conv = if upper { 'X' } else { 'x' };
            let fmt = format!("%{flags}{width}{p}{conv}");
            prop_assert_eq!(ours(&fmt, A::U32(v)), host(&fmt, false, v as i64), "fmt={}", fmt);
        }
        #[test]
        fn octal_matches(flags in flagset(), width in 0usize..14, v in any::<u32>()) {
            let fmt = format!("%{flags}{width}o");
            prop_assert_eq!(ours(&fmt, A::U32(v)), host(&fmt, false, v as i64), "fmt={}", fmt);
        }
    }
