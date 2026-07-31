use super::{EFI_BS_BASE, EFI_BS_COUNT, EFI_BS_PAGES, EFI_CMDLINE, EFI_CMDLINE_LEN, EFI_CMDLINE_MAX, EFI_RAM_BASE, EFI_RAM_COUNT, EFI_RAM_MAX, EFI_RAM_PAGES, EFI_RSDP_PA, EFI_TYPE_PAGES};

/// EFI device-tree config-table GUID (gFdtTableGuid,
/// b1b621d5-f19c-41a5-830b-d9152c69aae0) in EFI mixed-endian byte order:
/// Data1/2/3 little-endian, Data4 big-endian.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const FDT_TABLE_GUID: [u8; 16] = [
    0xd5, 0x21, 0xb6, 0xb1, 0x9c, 0xf1, 0xa5, 0x41,
    0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0,
];

/// EFI ACPI 2.0 config-table GUID (gEfiAcpi20TableGuid,
/// 8868e871-e4f1-11d3-bc22-0080c73c8881) in EFI mixed-endian byte order.
/// Its VendorTable pointer is the ACPI RSDP physical address.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const ACPI_20_TABLE_GUID: [u8; 16] = [
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11,
    0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
];

/// EFI loaded-image protocol GUID (gEfiLoadedImageProtocolGuid,
/// 5b1b31a1-9562-11d2-8e3f-00a0c969723b) in EFI mixed-endian byte order.
/// Its interface carries the command line the bootloader passed us.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const LOADED_IMAGE_GUID: [u8; 16] = [
    0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11,
    0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
];

/// `EFI_BOOT_SERVICES.HandleProtocol` slot (UEFI 2.x table order).
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const BS_HANDLE_PROTOCOL: usize = 0x98;
/// `EFI_LOADED_IMAGE_PROTOCOL.LoadOptionsSize` (UINT32) and `.LoadOptions`
/// (pointer) field offsets under LP64 natural alignment.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const LOADED_IMAGE_OPTIONS_SIZE: usize = 0x30;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const LOADED_IMAGE_OPTIONS: usize = 0x38;

/// Capture the bootloader command line from the loaded-image protocol's
/// UTF-16 `LoadOptions` into `EFI_CMDLINE`, decoded to UTF-8.
///
/// Must run while boot services are alive (before `ExitBootServices`) — the
/// protocol lookup is a boot-services call and the options buffer is
/// firmware-owned memory that need not survive the exit, so the bytes are
/// copied out here rather than referenced later.
///
/// # SAFETY: called once from `efi_stub_setup` with the firmware `handle` and
/// a live `boot_services` table; writes only the two boot-owned statics.
/// # C: O(load_options_size)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
unsafe fn capture_load_options(boot_services: *const u8, handle: u64) {
    // SAFETY: boot_services is the live EFI_BOOT_SERVICES table; the
    // HandleProtocol slot holds an AAPCS64 fn pointer per UEFI 2.x.
    unsafe {
        type HandleProtocolFn = extern "C" fn(u64, *const u8, *mut *const u8) -> u64;
        let handle_protocol: HandleProtocolFn =
            core::mem::transmute(*(boot_services.add(BS_HANDLE_PROTOCOL) as *const u64));
        let mut image: *const u8 = core::ptr::null();
        if handle_protocol(handle, LOADED_IMAGE_GUID.as_ptr(), &mut image) != 0 { return; }
        if image.is_null() { return; }
        let size = *(image.add(LOADED_IMAGE_OPTIONS_SIZE) as *const u32);
        let options = *(image.add(LOADED_IMAGE_OPTIONS) as *const *const u16);
        if options.is_null() { return; }
        let count = crate::efi_cmdline::load_options_units(size);
        if count == 0 { return; }
        let units = core::slice::from_raw_parts(options, count);
        let mut n = 0usize;
        crate::efi_cmdline::utf16_to_utf8(units, |b| {
            if n >= EFI_CMDLINE_MAX { return false; }
            EFI_CMDLINE[n].store(b, core::sync::atomic::Ordering::Release);
            n += 1;
            true
        });
        EFI_CMDLINE_LEN.store(n as u64, core::sync::atomic::Ordering::Release);
    }
}

/// EFI-stub bring-up, called from `_arm_entry` when entered MMU-on (GRUB
/// `linux` / UEFI LoadImage). Walks the EFI configuration table for the
/// flattened device tree, then sizes the memory map and calls
/// `ExitBootServices` (retry loop — the map key goes stale if the
/// firmware mutates the map between calls). Returns the DTB phys (== VA
/// under the firmware's identity map) for the trampoline; the caller
/// disables the MMU on return. Touches only its args, the stack, and the
/// firmware tables — no kernel statics (HHDM/klog aren't up yet).
///
/// EFI_SYSTEM_TABLE / EFI_BOOT_SERVICES field offsets per UEFI 2.x;
/// AArch64 UEFI uses AAPCS64 so the fn pointers are plain `extern "C"`.
///
/// # SAFETY: invoked once from the asm EFI entry with valid firmware
/// `handle`/`systab`; boot services live until ExitBootServices returns.
/// # C: O(config_entries + memmap_descriptors)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
pub unsafe extern "C" fn efi_stub_setup(handle: u64, systab: *const u8) -> u64 {
    // SAFETY: systab is the firmware EFI_SYSTEM_TABLE; offsets 0x60/0x68/
    // 0x70 are BootServices/NumberOfTableEntries/ConfigurationTable.
    unsafe {
        let boot_services = *(systab.add(0x60) as *const *const u8);
        let num_entries   = *(systab.add(0x68) as *const u64);
        let cfg_table     = *(systab.add(0x70) as *const *const u8);

        // Walk the config table (24 bytes each: 16-byte GUID + 8-byte
        // VendorTable pointer) for BOTH the FDT and the ACPI 2.0 RSDP. Don't
        // break early — UEFI may carry either or both, and we want each.
        let mut dtb: u64 = 0;
        let mut rsdp: u64 = 0;
        let mut i: u64 = 0;
        while i < num_entries {
            let ent = cfg_table.add((i * 24) as usize);
            let mut fdt_hit = true;
            let mut acpi_hit = true;
            let mut k = 0usize;
            while k < 16 {
                let b = *ent.add(k);
                if b != FDT_TABLE_GUID[k]  { fdt_hit = false; }
                if b != ACPI_20_TABLE_GUID[k] { acpi_hit = false; }
                k += 1;
            }
            if fdt_hit  { dtb  = *(ent.add(16) as *const u64); }
            if acpi_hit { rsdp = *(ent.add(16) as *const u64); }
            i += 1;
        }
        // Publish the RSDP for build_boot_info (FDT goes back in x0).
        EFI_RSDP_PA.store(rsdp, core::sync::atomic::Ordering::Release);

        // Command line, while boot services still answer protocol lookups.
        // SAFETY: same firmware contract as this fn's caller; boot services
        // are alive until the ExitBootServices below returns.
        capture_load_options(boot_services, handle);

        // GetMemoryMap @ bs+0x38, ExitBootServices @ bs+0xE8.
        type GetMemoryMapFn =
            extern "C" fn(*mut u64, *mut u8, *mut u64, *mut u64, *mut u32) -> u64;
        type ExitBootServicesFn = extern "C" fn(u64, u64) -> u64;
        let get_memory_map: GetMemoryMapFn =
            core::mem::transmute(*(boot_services.add(0x38) as *const u64));
        let exit_boot_services: ExitBootServicesFn =
            core::mem::transmute(*(boot_services.add(0xE8) as *const u64));

        // QEMU virt's map is a few KiB; 16 KiB of stack covers it.
        let mut buf = [0u8; 16384];
        let mut map_key: u64 = 0;
        let mut desc_size: u64 = 0;
        let mut desc_ver: u32 = 0;
        let mut tries = 0;
        loop {
            let mut map_size: u64 = buf.len() as u64;
            let _ = get_memory_map(
                &mut map_size, buf.as_mut_ptr(),
                &mut map_key, &mut desc_size, &mut desc_ver,
            );
            // Capture EfiConventionalMemory (type 7 = genuinely-free DRAM,
            // excludes the kernel image, ACPI tables, reserved + MMIO) so
            // build_selfboot_memmap can size the PMM from the real map when
            // the firmware exposes no FDT. Descriptor layout (UEFI 2.x):
            // Type u32 @0, PhysicalStart u64 @8, NumberOfPages u64 @24;
            // stride is the firmware-reported desc_size (>= 40).
            if desc_size >= 40 {
                let mut n = 0usize;
                let mut nb = 0usize;
                let mut off: u64 = 0;
                // Reset per-type tallies (loop may re-run on a stale map_key).
                let mut k = 0usize;
                while k < 16 { EFI_TYPE_PAGES[k].store(0, core::sync::atomic::Ordering::Release); k += 1; }
                while off + desc_size <= map_size {
                    let d = buf.as_ptr().add(off as usize);
                    let ty = *(d as *const u32);
                    let phys = *(d.add(8) as *const u64);
                    let pages = *(d.add(24) as *const u64);
                    if (ty as usize) < 16 {
                        EFI_TYPE_PAGES[ty as usize]
                            .fetch_add(pages, core::sync::atomic::Ordering::Release);
                    }
                    // type 7 = EfiConventionalMemory → unconditionally usable.
                    if ty == 7 && pages != 0 && n < EFI_RAM_MAX {
                        EFI_RAM_BASE[n].store(phys, core::sync::atomic::Ordering::Release);
                        EFI_RAM_PAGES[n].store(pages, core::sync::atomic::Ordering::Release);
                        n += 1;
                    }
                    // types 3/4 = BootServices Code/Data → reclaimable, but
                    // gated on ACPI being pinned (this EDK2 stores the live
                    // ACPI tables in type4; build_selfboot_memmap reserves the
                    // ACPI extent before adding these).
                    if (ty == 3 || ty == 4) && pages != 0 && nb < EFI_RAM_MAX {
                        EFI_BS_BASE[nb].store(phys, core::sync::atomic::Ordering::Release);
                        EFI_BS_PAGES[nb].store(pages, core::sync::atomic::Ordering::Release);
                        nb += 1;
                    }
                    off += desc_size;
                }
                EFI_RAM_COUNT.store(n as u64, core::sync::atomic::Ordering::Release);
                EFI_BS_COUNT.store(nb as u64, core::sync::atomic::Ordering::Release);
            }
            // ExitBootServices must immediately follow GetMemoryMap with
            // the fresh key; on EFI_INVALID_PARAMETER the map changed —
            // re-fetch and retry.
            if exit_boot_services(handle, map_key) == 0 { break; }
            tries += 1;
            if tries > 8 { break; }
        }
        dtb
    }
}

