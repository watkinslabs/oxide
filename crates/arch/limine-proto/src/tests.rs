use super::*;
use core::sync::atomic::AtomicPtr;

    #[test]
    fn common_magic_constants_match_limine_protocol() {
        // Pin these — bootloader relies on exact byte match.
        assert_eq!(LIMINE_COMMON_MAGIC_0, 0xc7b1_dd30_df4c_8b88);
        assert_eq!(LIMINE_COMMON_MAGIC_1, 0x0a82_e883_a194_f07b);
    }

    #[test]
    fn per_feature_ids_carry_common_magic() {
        for id in [MEMMAP_ID, HHDM_ID, RSDP_ID] {
            assert_eq!(id.0[0], LIMINE_COMMON_MAGIC_0,
                "request id {:?} missing common magic 0", id);
            assert_eq!(id.0[1], LIMINE_COMMON_MAGIC_1,
                "request id {:?} missing common magic 1", id);
        }
    }

    #[test]
    fn per_feature_magic_matches_limine_protocol_v12() {
        // Pin canonical magic words from
        // `limine-protocol/include/limine.h` (v12.x):
        //   LIMINE_MEMMAP_REQUEST_ID = { ..., 0x67cf3d9d378a806f, 0xe304acdfc50c3c62 }
        //   LIMINE_HHDM_REQUEST_ID   = { ..., 0x48dcf1cb8ad2b852, 0x63984e959a98244b }
        //   LIMINE_RSDP_REQUEST_ID   = { ..., 0xc5e77b6b397e7b43, 0x27637845accdcf3c }
        // A typo here means the bootloader scans for our marker and
        // never finds it, leaving `response` null — and silently so.
        assert_eq!(MEMMAP_ID.0[2], 0x67cf_3d9d_378a_806f);
        assert_eq!(MEMMAP_ID.0[3], 0xe304_acdf_c50c_3c62);
        assert_eq!(HHDM_ID.0[2],   0x48dc_f1cb_8ad2_b852);
        assert_eq!(HHDM_ID.0[3],   0x6398_4e95_9a98_244b);
        assert_eq!(RSDP_ID.0[2],   0xc5e7_7b6b_397e_7b43);
        assert_eq!(RSDP_ID.0[3],   0x2763_7845_accd_cf3c);
    }

    #[test]
    fn per_feature_ids_distinct() {
        assert_ne!(MEMMAP_ID, HHDM_ID);
        assert_ne!(MEMMAP_ID, RSDP_ID);
        assert_ne!(HHDM_ID,   RSDP_ID);
        assert_ne!(SMP_ID,    MEMMAP_ID);
        assert_ne!(SMP_ID,    HHDM_ID);
        assert_ne!(SMP_ID,    RSDP_ID);
    }

    #[test]
    fn smp_request_id_matches_limine_v12() {
        assert_eq!(SMP_ID.0[0], LIMINE_COMMON_MAGIC_0);
        assert_eq!(SMP_ID.0[1], LIMINE_COMMON_MAGIC_1);
        assert_eq!(SMP_ID.0[2], 0x95a6_7b81_9a1b_857e);
        assert_eq!(SMP_ID.0[3], 0xa0b6_1b72_3b6a_73e0);
    }

    #[test]
    fn smp_request_layout_has_flags_after_response() {
        // Pin the struct shape — the bootloader walks fields by offset.
        // Layout: id(32) + revision(8) + response_ptr(8) + flags(8) = 56.
        assert_eq!(core::mem::size_of::<SmpRequest>(), 32 + 8 + 8 + 8);
        // flags lives immediately after response.
        let r = SmpRequest {
            id: SMP_ID,
            revision: 0,
            response: AtomicPtr::new(core::ptr::null_mut()),
            flags: 0,
        };
        let base   = (&r as *const SmpRequest) as usize;
        let flag_o = (&r.flags as *const u64) as usize - base;
        assert_eq!(flag_o, 32 + 8 + 8);
    }

    #[test]
    fn smp_info_x86_layout() {
        // Limine v6 SmpInfoX86: processor_id(4) + lapic_id(4) +
        // reserved(8) + goto_address(8) + extra_argument(8) = 32.
        assert_eq!(core::mem::size_of::<SmpInfoX86>(), 32);
    }

    #[test]
    fn request_header_layout_is_24_plus_ptr() {
        // 32 B magic + 8 B revision + ptr-size response.
        let sz = core::mem::size_of::<RequestHeader<MemmapResponse>>();
        assert_eq!(sz, 32 + 8 + core::mem::size_of::<*mut MemmapResponse>());
    }

    #[test]
    fn memmap_kind_round_trip() {
        for raw in 0..=7u64 {
            let k = MemmapKind::from_u64(raw).unwrap();
            assert_eq!(k as u64, raw);
        }
        assert!(MemmapKind::from_u64(99).is_none());
    }

    #[test]
    fn memmap_kind_to_kernel_kind_maps_usable() {
        assert_eq!(MemmapKind::Usable.to_kernel_kind(),    boot_info::BootMemKind::Usable);
        assert_eq!(MemmapKind::Reserved.to_kernel_kind(),  boot_info::BootMemKind::Reserved);
        assert_eq!(MemmapKind::AcpiReclaimable.to_kernel_kind(),
                   boot_info::BootMemKind::AcpiReclaim);
        assert_eq!(MemmapKind::AcpiNvs.to_kernel_kind(),   boot_info::BootMemKind::AcpiNvs);
        assert_eq!(MemmapKind::BadMemory.to_kernel_kind(), boot_info::BootMemKind::BadMem);
    }

    extern crate alloc;

    fn fake_memmap(entries: &[(u64, u64, u64)])
        -> (alloc::vec::Vec<MemmapEntry>, alloc::vec::Vec<*const MemmapEntry>)
    {
        let mut backing: alloc::vec::Vec<MemmapEntry> = entries.iter()
            .map(|(b, l, k)| MemmapEntry { base: *b, length: *l, kind: *k })
            .collect();
        let mut ptrs: alloc::vec::Vec<*const MemmapEntry> = backing.iter_mut()
            .map(|e| e as *const _)
            .collect();
        let _ = &mut ptrs;
        (backing, ptrs)
    }

    #[test]
    fn populate_memmap_writes_each_entry() {
        let (_backing, ptrs) = fake_memmap(&[
            (0x0000_0000, 0x000a_0000, 0), // Usable, 640 KiB
            (0x000a_0000, 0x0006_0000, 1), // Reserved
            (0x0010_0000, 0x4000_0000, 5), // BootloaderReclaimable
        ]);
        let resp = MemmapResponse {
            revision:    0,
            entry_count: ptrs.len() as u64,
            entries:     ptrs.as_ptr(),
        };
        let mut out = [boot_info::BootMemRegion {
            base_pa: 0, len: 0, kind: boot_info::BootMemKind::Reserved,
        }; 8];
        // SAFETY: hosted test; ptrs/backing live across this call.
        let n = unsafe { populate_memmap_into(&mut out, &resp) };
        assert_eq!(n, 3);
        assert_eq!(out[0].base_pa, 0);
        assert_eq!(out[0].kind,    boot_info::BootMemKind::Usable);
        assert_eq!(out[1].kind,    boot_info::BootMemKind::Reserved);
        assert_eq!(out[2].kind,    boot_info::BootMemKind::BootloaderUsed);
        assert_eq!(out[2].len,     0x4000_0000);
    }

    #[test]
    fn populate_memmap_caps_at_out_len() {
        let (_backing, ptrs) = fake_memmap(&[
            (0, 0x1000, 0), (0x1000, 0x1000, 0), (0x2000, 0x1000, 0),
            (0x3000, 0x1000, 0),
        ]);
        let resp = MemmapResponse {
            revision: 0, entry_count: 4, entries: ptrs.as_ptr(),
        };
        let mut out = [boot_info::BootMemRegion {
            base_pa: 0, len: 0, kind: boot_info::BootMemKind::Reserved,
        }; 2];
        // SAFETY: hosted test; pointers live across the call.
        let n = unsafe { populate_memmap_into(&mut out, &resp) };
        assert_eq!(n, 2, "must cap at out.len() per spec");
        assert_eq!(out[0].base_pa, 0);
        assert_eq!(out[1].base_pa, 0x1000);
    }

    #[test]
    fn populate_memmap_unknown_kind_falls_back_to_reserved() {
        let (_backing, ptrs) = fake_memmap(&[(0, 0x1000, 99)]);
        let resp = MemmapResponse {
            revision: 0, entry_count: 1, entries: ptrs.as_ptr(),
        };
        let mut out = [boot_info::BootMemRegion {
            base_pa: 0, len: 0, kind: boot_info::BootMemKind::Usable,
        }; 1];
        // SAFETY: hosted test; pointers live across the call.
        let n = unsafe { populate_memmap_into(&mut out, &resp) };
        assert_eq!(n, 1);
        assert_eq!(out[0].kind, boot_info::BootMemKind::Reserved,
            "unknown kind must fall back to Reserved");
    }
