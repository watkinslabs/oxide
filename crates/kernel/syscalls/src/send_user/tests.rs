// Hosted coverage for the send-message importer: operand ordering, the
// control-length screen, and the native entry's rejection of the compat
// message layout.

    use super::*;

    fn put_u32(out: &mut [u8], at: usize, value: u32) {
        out[at..at + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn put_u64(out: &mut [u8], at: usize, value: u64) {
        out[at..at + 8].copy_from_slice(&value.to_ne_bytes());
    }

    fn header(name: &[u8], control: &[u8], iovp: u64, iovlen: u64) -> [u8; MSGHDR_LEN] {
        let mut out = [0u8; MSGHDR_LEN];
        put_u64(&mut out, 0, name.as_ptr() as u64);
        put_u32(&mut out, 8, name.len() as u32);
        put_u64(&mut out, 16, iovp);
        put_u64(&mut out, 24, iovlen);
        put_u64(&mut out, 32, control.as_ptr() as u64);
        put_u64(&mut out, 40, control.len() as u64);
        out
    }

    fn iovec(out: &mut [u8], at: usize, bytes: &[u8]) {
        put_u64(out, at, bytes.as_ptr() as u64);
        put_u64(out, at + 8, bytes.len() as u64);
    }

    #[test]
    fn imports_unaligned_header_and_complete_unaligned_iovec_array() {
        let a = b"abc";
        let b = b"de";
        let mut raw = [0u8; IOVEC_LEN * 2 + 1];
        iovec(&mut raw, 1, a);
        iovec(&mut raw, 1 + IOVEC_LEN, b);
        let h = header(&[], &[], raw[1..].as_ptr() as u64, 2);
        let mut unaligned = [0u8; MSGHDR_LEN + 1];
        unaligned[1..].copy_from_slice(&h);

        let imported = import(unaligned[1..].as_ptr() as u64).unwrap();
        assert_eq!(imported.payload, b"abcde");
        assert_eq!(imported.requested_len, 5);
    }

    #[test]
    fn rejects_iov_count_with_linux_emsgsize() {
        let h = header(&[], &[], 0, (UIO_MAXIOV + 1) as u64);
        assert_eq!(import(h.as_ptr() as u64).err(), Some(errno(Errno::Emsgsize)));
    }

    #[test]
    fn imports_compat_mmsghdr_layout_without_reading_native_widths() {
        let mut hdr = [0u8; COMPAT_MSGHDR_LEN];
        put_u32(&mut hdr, 4, 0);
        put_u32(&mut hdr, 12, 0);
        put_u32(&mut hdr, 20, 0);
        let imported = import_compat(hdr.as_ptr() as u64).unwrap();
        assert_eq!(imported.requested_len, 0);
        assert!(imported.payload.is_empty());
    }

    #[test]
    fn caps_saturating_iovec_total_at_max_rw_count() {
        let iov = [IoVec { base: 1, len: MAX_RW_COUNT - 1 },
            IoVec { base: 1, len: usize::MAX }];
        assert_eq!(capped_total(&iov), MAX_RW_COUNT);
    }

    #[test]
    fn payload_fault_returns_prefix_or_efault() {
        let iov = [IoVec { base: 10, len: 4 }, IoVec { base: 20, len: 3 }];
        let (copied, faulted) = gather_with(&iov, 7, |dst, src, len| {
            let bytes = if src == 10 { b"abcd".as_slice() } else { b"xy".as_slice() };
            let n = core::cmp::min(len, bytes.len());
            // SAFETY: gather_with provides n writable bytes and bytes contains n readable bytes.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, n); }
            len - n
        }).unwrap();
        assert_eq!(copied, b"abcdxy");
        assert!(faulted);

        assert_eq!(gather_with(&iov, 7, |_dst, _src, len| len).err(),
            Some(errno(Errno::Efault)));
    }

    #[test]
    fn copies_payload_control_and_name_into_kernel_vecs() {
        let a = b"payload ";
        let b = b"bytes";
        let name = b"sockaddr";
        let control = b"ancillary";
        let mut raw = [0u8; IOVEC_LEN * 2];
        iovec(&mut raw, 0, a);
        iovec(&mut raw, IOVEC_LEN, b);
        let h = header(name, control, raw.as_ptr() as u64, 2);

        let imported = import(h.as_ptr() as u64).unwrap();
        assert_eq!(imported.payload, b"payload bytes");
        assert_eq!(imported.requested_len, b"payload bytes".len());
        assert_eq!(imported.control, control);
        assert_eq!(imported.name.as_deref(), Some(name.as_slice()));
    }

    #[test]
    fn null_or_zero_length_message_name_is_absent() {
        let mut null = header(&[], &[], 0, 0);
        put_u64(&mut null, 0, 0);
        put_u32(&mut null, 8, u32::MAX);
        let mut present = null;
        put_u64(&mut present, 0, [0u8; 1].as_ptr() as u64);
        put_u32(&mut present, 8, 0);
        assert_eq!(import(null.as_ptr() as u64).unwrap().name, None);
        assert_eq!(import(present.as_ptr() as u64).unwrap().name, None);
    }

    #[test]
    fn name_errors_precede_iovlen_validation_for_sendmsg_and_sendmmsg_import() {
        let too_many = (UIO_MAXIOV + 1) as u64;
        let fault = |_src, _len| Err(errno(Errno::Efault));
        assert_eq!(import_name_and_iovlen_with(1, 1, too_many, fault).err(),
            Some(errno(Errno::Efault)));
        assert_eq!(import_name_and_iovlen_with(1, u32::MAX, too_many, fault).err(),
            Some(errno(Errno::Einval)));
        assert_eq!(import_name_and_iovlen_with(0, u32::MAX, too_many, fault).err(),
            Some(errno(Errno::Emsgsize)));
        assert_eq!(import_name_and_iovlen_with(1, 0, too_many, fault).err(),
            Some(errno(Errno::Emsgsize)));

        let name = [0u8; 1];
        let mut before_iov_import = header(&[], &[], 1, 1);
        put_u64(&mut before_iov_import, 0, name.as_ptr() as u64);
        put_u32(&mut before_iov_import, 8, u32::MAX);
        assert_eq!(import(before_iov_import.as_ptr() as u64).err(), Some(errno(Errno::Einval)));
    }

    #[test]
    fn oversized_message_name_is_clamped_to_sockaddr_storage() {
        // Linux `__copy_msghdr` clamps `msg_namelen > sockaddr_storage` and
        // sends; only the copied 128-byte prefix is retained (the address
        // parser reads the family's struct from it).
        let name = [0x5au8; SOCKADDR_STORAGE_LEN + 8];
        let mut h = header(&[], &[], 0, 0);
        put_u64(&mut h, 0, name.as_ptr() as u64);
        put_u32(&mut h, 8, (SOCKADDR_STORAGE_LEN + 8) as u32);
        let message = import(h.as_ptr() as u64).expect("clamped name import succeeds");
        assert_eq!(message.name.as_ref().map(|n| n.len()), Some(SOCKADDR_STORAGE_LEN));
    }

    #[test]
    fn iovec_fault_precedes_excessive_control_length() {
        let mut iov = [0u8; IOVEC_LEN];
        put_u64(&mut iov, 0, u64::MAX);
        put_u64(&mut iov, 8, 2);
        let mut h = header(&[], &[], 0, 0);
        put_u64(&mut h, 16, iov.as_ptr() as u64);
        put_u64(&mut h, 24, 1);
        put_u64(&mut h, 40, (net::sysctl::optmem_max() + 1) as u64);
        assert_eq!(import(h.as_ptr() as u64).err(), Some(errno(Errno::Efault)));
    }

    #[test]
    fn native_compat_flag_precedes_task_and_fd_lookup() {
        for name in [include_str!("../046_sendmsg.rs"), include_str!("../307_sendmmsg.rs")] {
            let compat = name.find("MSG_CMSG_COMPAT").unwrap();
            let current = name.find("sched::live::current()").unwrap();
            assert!(compat < current, "the native entry rejects the compat layout first");
        }
        // The batch spec carries the caller's flags unmasked, so the one
        // owner that screens the compat layout cannot be bypassed by the shim
        // stripping the bit before handing the batch over.
        let batch = include_str!("../307_sendmmsg.rs");
        assert!(batch.contains("flags: args.a3 as u32"));
        assert!(!batch.contains("new_compat"));

        let sendto = include_str!("../044_sendto.rs");
        let readable = sendto.find("validate_user_buf_readable").unwrap();
        let current = sendto.find("sched::live::current()").unwrap();
        assert!(readable < current);
    }
