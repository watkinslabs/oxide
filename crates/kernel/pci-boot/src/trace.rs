use crate::map_mmio_pages;

/// Emit one `[INFO] pci-bar <bdf> N <kind>=...` line per programmed BAR.
/// # C: O(1) — at most 6 BARs.
pub(crate) fn bar_dump_arch(bdf: pci::Bdf) {
    #[cfg(not(feature = "debug-boot"))]
    let _ = bdf;
    debug_boot! {
        let bars = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::LegacyPci;
                pci::decode_bars(&r, bdf)
            }
            #[cfg(target_arch = "aarch64")]
            {
                match hal_aarch64::pci::EcamPci::from_published() {
                    Some(r) => pci::decode_bars(&r, bdf),
                    None    => [pci::Bar::None; 6],
                }
            }
        };
        for (i, b) in bars.iter().enumerate() {
            match *b {
                pci::Bar::None | pci::Bar::HighHalfConsumed => continue,
                pci::Bar::Io { port } => {
                    klog::write_raw(b"[INFO]  pci-bar ");
                    klog::write_dec_u64(bdf.bus as u64);
                    klog::write_raw(b":");
                    klog::write_dec_u64(bdf.device as u64);
                    klog::write_raw(b".");
                    klog::write_dec_u64(bdf.function as u64);
                    klog::write_raw(b" b");
                    klog::write_dec_u64(i as u64);
                    klog::write_raw(b" io=");
                    klog::write_hex_u64(port as u64);
                    klog::write_raw(b"\n");
                }
                pci::Bar::Mem32 { base, prefetch } => {
                    klog::write_raw(b"[INFO]  pci-bar ");
                    klog::write_dec_u64(bdf.bus as u64);
                    klog::write_raw(b":");
                    klog::write_dec_u64(bdf.device as u64);
                    klog::write_raw(b".");
                    klog::write_dec_u64(bdf.function as u64);
                    klog::write_raw(b" b");
                    klog::write_dec_u64(i as u64);
                    klog::write_raw(b" mem32=");
                    klog::write_hex_u64(base as u64);
                    if prefetch { klog::write_raw(b" pf"); }
                    klog::write_raw(b"\n");
                }
                pci::Bar::Mem64 { base, prefetch } => {
                    klog::write_raw(b"[INFO]  pci-bar ");
                    klog::write_dec_u64(bdf.bus as u64);
                    klog::write_raw(b":");
                    klog::write_dec_u64(bdf.device as u64);
                    klog::write_raw(b".");
                    klog::write_dec_u64(bdf.function as u64);
                    klog::write_raw(b" b");
                    klog::write_dec_u64(i as u64);
                    klog::write_raw(b" mem64=");
                    klog::write_hex_u64(base);
                    if prefetch { klog::write_raw(b" pf"); }
                    klog::write_raw(b"\n");
                }
            }
        }
    }
}

/// Per-arch wrapper that walks the capability list for one BDF and
/// emits `[INFO] pci-cap ... id=...` lines. For modern virtio devices
/// (vendor=0x1AF4, device=0x1041..=0x107f) it also decodes each vendor cap and
/// emits a `[INFO] virtio-cap ...` line per cfg_type.
/// # C: O(N_caps) — typical N is 1–6.
pub(crate) fn cap_dump_arch(d: &pci::PciDevice) {
    let bdf = d.bdf;
    #[cfg(not(feature = "debug-boot"))]
    let _ = bdf;
    debug_boot! {
        let caps = {
            #[cfg(target_arch = "x86_64")]
            {
                let r = hal_x86_64::pci::LegacyPci;
                pci::capabilities(&r, bdf)
            }
            #[cfg(target_arch = "aarch64")]
            {
                match hal_aarch64::pci::EcamPci::from_published() {
                    Some(r) => pci::capabilities(&r, bdf),
                    None    => pci::heapless_caps::CapVec::new(),
                }
            }
        };
        for c in caps.iter() {
            klog::write_raw(b"[INFO]  pci-cap ");
            klog::write_dec_u64(bdf.bus as u64);
            klog::write_raw(b":");
            klog::write_dec_u64(bdf.device as u64);
            klog::write_raw(b".");
            klog::write_dec_u64(bdf.function as u64);
            klog::write_raw(b" id=");
            klog::write_hex_u64(c.id as u64);
            klog::write_raw(b" off=");
            klog::write_hex_u64(c.cfg_off as u64);
            klog::write_raw(b"\n");
            if c.id == pci::CAP_ID_MSIX {
                let mx = {
                    #[cfg(target_arch = "x86_64")]
                    {
                        let r = hal_x86_64::pci::LegacyPci;
                        pci::decode_msix_cap(&r, bdf, c.cfg_off)
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        match hal_aarch64::pci::EcamPci::from_published() {
                            Some(r) => pci::decode_msix_cap(&r, bdf, c.cfg_off),
                            None => None,
                        }
                    }
                };
                if let Some(m) = mx {
                    klog::write_raw(b"[INFO]  msix ");
                    klog::write_dec_u64(bdf.bus as u64);
                    klog::write_raw(b":");
                    klog::write_dec_u64(bdf.device as u64);
                    klog::write_raw(b".");
                    klog::write_dec_u64(bdf.function as u64);
                    klog::write_raw(b" enable=");
                    klog::write_dec_u64(m.enabled as u64);
                    klog::write_raw(b" fn_mask=");
                    klog::write_dec_u64(m.function_mask as u64);
                    klog::write_raw(b" n=");
                    klog::write_dec_u64(m.table_size as u64);
                    klog::write_raw(b" tbl_bir=");
                    klog::write_dec_u64(m.table_bir as u64);
                    klog::write_raw(b" tbl_off=");
                    klog::write_hex_u64(m.table_offset as u64);
                    klog::write_raw(b" pba_bir=");
                    klog::write_dec_u64(m.pba_bir as u64);
                    klog::write_raw(b" pba_off=");
                    klog::write_hex_u64(m.pba_offset as u64);
                    klog::write_raw(b"\n");

                    let bars2 = {
                        #[cfg(target_arch = "x86_64")]
                        {
                            let r = hal_x86_64::pci::LegacyPci;
                            pci::decode_bars(&r, bdf)
                        }
                        #[cfg(target_arch = "aarch64")]
                        {
                            match hal_aarch64::pci::EcamPci::from_published() {
                                Some(r) => pci::decode_bars(&r, bdf),
                                None => [pci::Bar::None; 6],
                            }
                        }
                    };
                    let tbar_pa = match bars2[m.table_bir as usize] {
                        pci::Bar::Mem32 { base, .. } => base as u64,
                        pci::Bar::Mem64 { base, .. } => base,
                        _ => 0,
                    };
                    if tbar_pa != 0 {
                        let tbl_pa = tbar_pa + m.table_offset as u64;
                        let page_pa = tbl_pa & !0xFFF;
                        let page_off = tbl_pa - page_pa;
                        let base_va = unsafe { map_mmio_pages(page_pa, 1) };
                        let tbl_va = base_va + page_off;
                        let n = if m.table_size > 4 { 4 } else { m.table_size };
                        for i in 0..n {
                            let entry_va = tbl_va + (i as u64) * 16;
                            let vc = unsafe {
                                core::ptr::read_volatile((entry_va + 12) as *const u32)
                            };
                            klog::write_raw(b"[INFO]  msix-tbl ");
                            klog::write_dec_u64(bdf.bus as u64);
                            klog::write_raw(b":");
                            klog::write_dec_u64(bdf.device as u64);
                            klog::write_raw(b".");
                            klog::write_dec_u64(bdf.function as u64);
                            klog::write_raw(b" v=");
                            klog::write_dec_u64(i as u64);
                            klog::write_raw(b" ctl=");
                            klog::write_hex_u64(vc as u64);
                            klog::write_raw(b" masked=");
                            klog::write_dec_u64((vc & 0x1) as u64);
                            klog::write_raw(b"\n");
                        }
                        unsafe { mmio_map::unmap_pages(base_va, 1); }
                    }
                }
            }
        }
        if virtio::is_modern(d.vendor_id, d.device_id) {
            let vcaps = {
                #[cfg(target_arch = "x86_64")]
                {
                    let r = hal_x86_64::pci::LegacyPci;
                    virtio::decode_all(&r, bdf, &caps)
                }
                #[cfg(target_arch = "aarch64")]
                {
                    match hal_aarch64::pci::EcamPci::from_published() {
                        Some(r) => virtio::decode_all(&r, bdf, &caps),
                        None => virtio::pci::heapless_v::VCapVec::new(),
                    }
                }
            };
            for v in vcaps.iter() {
                klog::write_raw(b"[INFO]  virtio-cap ");
                klog::write_dec_u64(bdf.bus as u64);
                klog::write_raw(b":");
                klog::write_dec_u64(bdf.device as u64);
                klog::write_raw(b".");
                klog::write_dec_u64(bdf.function as u64);
                klog::write_raw(b" type=");
                klog::write_dec_u64(v.cfg_type as u64);
                klog::write_raw(b" bar=");
                klog::write_dec_u64(v.bar as u64);
                klog::write_raw(b" off=");
                klog::write_hex_u64(v.offset as u64);
                klog::write_raw(b" len=");
                klog::write_hex_u64(v.length as u64);
                if v.cfg_type == virtio::VIRTIO_PCI_CAP_NOTIFY_CFG {
                    klog::write_raw(b" notify_mult=");
                    klog::write_hex_u64(v.notify_off_multiplier as u64);
                }
                klog::write_raw(b"\n");
            }
        }
    }
}
