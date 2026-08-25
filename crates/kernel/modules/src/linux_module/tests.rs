    use super::*;
    use core::ptr::null;

    fn module(state: usize, refcnt: u32) -> LinuxModule {
        LinuxModule { name: null(), state, refcnt }
    }

    #[test]
    fn null_owner_is_builtin_and_gettable() {
        let _modules = crate::test_serial::claim();
        // SAFETY: NULL is the built-in-module owner in Linux's KPI and try_module_get's first
        // statement returns before any dereference, so no module storage is touched.
        let got = unsafe { try_module_get(core::ptr::null_mut()) };
        assert_eq!(got, 1);
        // SAFETY: module_put likewise returns on a NULL owner before reaching refcnt().
        unsafe { module_put(core::ptr::null_mut()) };
    }

    #[test]
    fn live_and_coming_modules_are_refcounted() {
        let _modules = crate::test_serial::claim();
        for state in [MODULE_STATE_LIVE, MODULE_STATE_COMING] {
            let mut m = module(state, 1);
            // SAFETY: m is the fully initialised LinuxModule on this test's stack, so it stands in
            // for the live struct module try_module_get expects and outlives both calls.
            assert_eq!(unsafe { try_module_get(&mut m) }, 1);
            assert_eq!(m.refcnt, 2);
            // SAFETY: same stack module, still live, and its refcnt is 2 so the drop is balanced.
            unsafe { module_put(&mut m) };
            assert_eq!(m.refcnt, 1);
        }
    }

    #[test]
    fn going_or_unknown_modules_refuse_new_refs() {
        let _modules = crate::test_serial::claim();
        for state in [MODULE_STATE_GOING, 99] {
            let mut m = module(state, 4);
            // SAFETY: m is this test's stack LinuxModule, initialised with the GOING/unknown state
            // under test, and it stays borrowed for the whole call.
            assert_eq!(unsafe { try_module_get(&mut m) }, 0);
            assert_eq!(m.refcnt, 4);
        }
    }

    #[test]
    fn saturated_modules_refuse_new_refs() {
        let _modules = crate::test_serial::claim();
        let mut m = module(MODULE_STATE_LIVE, u32::MAX);
        // SAFETY: m is this test's stack LinuxModule, initialised LIVE with a saturated refcnt, so
        // it is a valid target for the atomic fetch_update try_module_get performs on it.
        assert_eq!(unsafe { try_module_get(&mut m) }, 0);
        assert_eq!(m.refcnt, u32::MAX);
    }

    #[test]
    fn module_put_saturates_at_zero() {
        let _modules = crate::test_serial::claim();
        let mut m = module(MODULE_STATE_LIVE, 0);
        // SAFETY: m is this test's stack LinuxModule with refcnt 0; module_put only runs a
        // checked_sub fetch_update on that field, which is initialised and lives past the call.
        unsafe { module_put(&mut m) };
        assert_eq!(m.refcnt, 0);
    }

    #[test]
    fn scalar_params_parse_and_render_values() {
        let _modules = crate::test_serial::claim();
        let mut int_v = 0i32;
        let kp = KernelParam { name: null(), mod_: core::ptr::null_mut(), ops: &param_ops_int, perm: 0, level: 0, flags: 0, arg: (&mut int_v as *mut i32).cast() };
        // SAFETY: the value string is the NUL-terminated b"-42\0" literal, and kp.arg is the
        // address of int_v, an i32 on this stack frame, which is the type param_set_int writes.
        assert_eq!(unsafe { param_set_int(b"-42\0".as_ptr().cast(), &kp) }, 0);
        assert_eq!(int_v, -42);
        let mut out = [0 as c_char; 32];
        // SAFETY: param_get_int writes "-42\n" plus a NUL, 5 bytes, into out — a 32-element
        // c_char array on this stack frame — and reads the same live int_v through kp.
        assert_eq!(unsafe { param_get_int(out.as_mut_ptr(), &kp) }, 4);
        assert_eq!(bytes(&out), b"-42\n");

        let mut bool_v = false;
        let kp = KernelParam { name: null(), mod_: core::ptr::null_mut(), ops: &param_ops_bool, perm: 0, level: 0, flags: 0, arg: (&mut bool_v as *mut bool).cast() };
        // SAFETY: b"on\0" is NUL-terminated and kp.arg is the address of bool_v, a live bool on
        // this stack frame — the exact type param_set_bool stores through.
        assert_eq!(unsafe { param_set_bool(b"on\0".as_ptr().cast(), &kp) }, 0);
        assert!(bool_v);
    }

    #[test]
    fn byte_params_accept_only_unsigned_byte_values() {
        let _modules = crate::test_serial::claim();
        let mut value = 1u8;
        let kp = KernelParam { name: null(), mod_: core::ptr::null_mut(), ops: &param_ops_byte, perm: 0, level: 0, flags: 0, arg: (&mut value as *mut u8).cast() };
        // SAFETY: kp.arg names the live u8 backing value and the decimal input is NUL-terminated.
        assert_eq!(unsafe { param_set_byte(b"255\0".as_ptr().cast(), &kp) }, 0);
        assert_eq!(value, u8::MAX);
        // SAFETY: overflow input uses the same valid parameter and must fail before storing.
        assert_eq!(unsafe { param_set_byte(b"256\0".as_ptr().cast(), &kp) }, -LINUX_EINVAL);
        assert_eq!(value, u8::MAX);
    }

    #[test]
    fn uint_minmax_validates_before_storing() {
        let _modules = crate::test_serial::claim();
        let mut value = 17u32;
        let kp = KernelParam { name: null(), mod_: core::ptr::null_mut(), ops: &param_ops_uint, perm: 0, level: 0, flags: 0, arg: (&mut value as *mut u32).cast() };
        // SAFETY: kp.arg names the live u32 backing storage and each literal is NUL-terminated.
        assert_eq!(unsafe { params::param_set_uint_minmax(b"8\0".as_ptr().cast(), &kp, 8, 32) }, 0);
        assert_eq!(value, 8);
        // SAFETY: the out-of-range value uses the same valid parameter storage; rejection must
        // occur before the backing value is written.
        assert_eq!(unsafe { params::param_set_uint_minmax(b"33\0".as_ptr().cast(), &kp, 8, 32) }, -LINUX_EINVAL);
        assert_eq!(value, 8);
        // SAFETY: malformed input is NUL-terminated and must not mutate the valid backing value.
        assert_eq!(unsafe { params::param_set_uint_minmax(b"bad\0".as_ptr().cast(), &kp, 8, 32) }, -LINUX_EINVAL);
        assert_eq!(value, 8);
    }

    #[test]
    fn array_params_walk_element_ops() {
        let _modules = crate::test_serial::claim();
        let mut vals = [0u32; 3];
        let mut num = 0u32;
        let arr = KParamArray { max: 3, elemsize: core::mem::size_of::<u32>() as u32, num: &mut num, ops: &param_ops_uint, elem: vals.as_mut_ptr().cast() };
        let kp = KernelParam { name: null(), mod_: core::ptr::null_mut(), ops: &param_array_ops, perm: 0, level: 0, flags: 0, arg: (&arr as *const KParamArray as *mut KParamArray).cast() };
        // SAFETY: kp.arg is &arr, whose elem/num point at the live `vals` and `num` locals and
        // whose max=3 / elemsize=4 describe that [u32; 3] exactly, so every element store
        // param_array_set makes through param_ops_uint lands inside vals.
        assert_eq!(unsafe { param_array_set(b"1, 2, 0x10\0".as_ptr().cast(), &kp) }, 0);
        assert_eq!(num, 3);
        assert_eq!(vals, [1, 2, 16]);
        let mut out = [0 as c_char; 64];
        // SAFETY: out is a 64-element c_char stack array and the rendered "1,2,16\n\0" is 8 bytes,
        // so every write param_array_get makes stays in bounds; arr/vals/num are still live.
        assert_eq!(unsafe { param_array_get(out.as_mut_ptr(), &kp) }, 7);
        assert_eq!(bytes(&out), b"1,2,16\n");
    }

    fn bytes(s: &[c_char]) -> &[u8] {
        let n = s.iter().position(|&c| c == 0).unwrap();
        // SAFETY: c_char array is stored byte-for-byte for test comparison.
        unsafe { core::slice::from_raw_parts(s.as_ptr().cast::<u8>(), n) }
    }
