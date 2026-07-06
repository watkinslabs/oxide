use super::regs::{
    CBASER_IC_NC, CBASER_INNER_SH, CBASER_PS_4K, CBASER_SIZE_1PG, CBASER_VALID,
};
use super::*;

    #[test]
    fn typer_field_decoders_zero_extend() {
        // typer=0 implies the smallest legal encoding: 1-bit IDs,
        // 1-byte ITT entries, 1-bit DeviceID space.
        assert_eq!(typer_id_bits(0), 1);
        assert_eq!(typer_devbits(0), 1);
        assert_eq!(typer_itt_entry_size(0), 1);
        assert!(!typer_phys_lpi(0));
        assert!(!typer_virt_lpi(0));
    }

    #[test]
    fn typer_field_decoders_qemu_virt() {
        // QEMU virt + GICv3 ITS reports typer=0x000001f0001efb1:
        //   bit0=1 (physical), [7:4]=b=12-byte ITT entry,
        //   [12:8]=15→16 EventID bits, [17:13]=15→16 DeviceID bits.
        let t = 0x000001f0001efb1u64;
        assert!(typer_phys_lpi(t));
        assert!(!typer_virt_lpi(t));
        assert_eq!(typer_itt_entry_size(t), 12);
        assert_eq!(typer_id_bits(t), 16);
        assert_eq!(typer_devbits(t), 16);
    }

    #[test]
    fn status_distinct() {
        let a = ItsStatus::Absent;
        let b = ItsStatus::AlreadyOn;
        let c = ItsStatus::Discovered { typer: 0, ctlr: 0, iidr: 0, baser0: 0 };
        assert_ne!(a, b);
        assert_ne!(b, c);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cmd_mapd_encoding() {
        // DeviceID=0x10, ITT_pa=0x4a6f3000, Size=4.
        let c = cmd_mapd(0x10, 0x4a6f3000, 4);
        assert_eq!(c[0] & 0xFF, 0x08);                  // opcode
        assert_eq!((c[0] >> 32) & 0xFFFF_FFFF, 0x10);   // DeviceID
        assert_eq!(c[1] & 0x1f, 4);                     // Size
        assert!(c[2] & (1 << 63) != 0);                 // Valid
        assert_eq!(c[2] & 0x000F_FFFF_FFFF_FF00, 0x4a6f3000);
        assert_eq!(c[3], 0);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cmd_mapti_encoding() {
        let c = cmd_mapti(0x10, 0, 8192, 0);
        assert_eq!(c[0] & 0xFF, 0x0a);
        assert_eq!((c[0] >> 32) & 0xFFFF_FFFF, 0x10);
        assert_eq!(c[1] & 0xFFFF_FFFF, 0);
        assert_eq!((c[1] >> 32) & 0xFFFF_FFFF, 8192);
        assert_eq!(c[2] & 0xFFFF, 0);
        assert_eq!(c[3], 0);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cmd_inv_encoding() {
        let c = cmd_inv(0x10, 7);
        assert_eq!(c[0] & 0xFF, 0x0c);
        assert_eq!((c[0] >> 32) & 0xFFFF_FFFF, 0x10);
        assert_eq!(c[1], 7);
        assert_eq!(c[2], 0);
        assert_eq!(c[3], 0);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cmd_sync_encoding() {
        let c = cmd_sync(0);
        assert_eq!(c[0] & 0xFF, 0x05);
        assert_eq!(c[1], 0);
        assert_eq!(c[2], 0);
        assert_eq!(c[3], 0);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cmd_mapc_encoding() {
        // ICID=0, RDbase=0 (boot CPU, processor number).
        let c = cmd_mapc(0, 0);
        assert_eq!(c[0] & 0xFF, 0x09);
        assert_eq!(c[1], 0);
        assert!(c[2] & (1 << 63) != 0);
        assert_eq!(c[2] & 0xFFFF, 0);
        assert_eq!(c[3], 0);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn cbaser_compose_layout() {
        // Sample PA = 0x4_0000_1000 (4 KiB-aligned). Composition
        // should set Valid+IC+Sh, place PA in [47:12], and leave
        // Size/PageSize=0.
        let pa: u64 = 0x4_0000_1000;
        let v = CBASER_VALID
              | CBASER_IC_NC
              | CBASER_INNER_SH
              | CBASER_PS_4K
              | CBASER_SIZE_1PG
              | (pa & 0x0000_FFFF_FFFF_F000);
        assert!(v & (1 << 63) != 0);            // Valid
        assert!(v & (1 << 59) != 0);            // Inner-NC
        assert!(v & (1 << 10) != 0);            // Inner-Sh
        assert_eq!(v & 0xFF, 0);                // Size=0
        assert_eq!(v & 0x300, 0);               // PageSize=0
        assert_eq!(v & 0x0000_FFFF_FFFF_F000, pa);
    }
