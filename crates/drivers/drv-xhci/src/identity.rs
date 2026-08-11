use pci::Bdf;

/// Encode one controller function and xHCI slot into a distinct input identity. # C: O(1)
pub const fn input_platform_id(bdf: Bdf, slot: u8) -> u32 {
    ((slot as u32) << 16) | ((bdf.bus as u32) << 8) | ((bdf.device as u32) << 3) | bdf.function as u32
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn root_port_devices_keep_distinct_input_identities() {
        let bdf = Bdf { segment: 0, bus: 0, device: 20, function: 0 };
        assert_ne!(input_platform_id(bdf, 1), input_platform_id(bdf, 2));
        assert_ne!(input_platform_id(bdf, 1), input_platform_id(Bdf { bus: 1, ..bdf }, 1));
    }
}
