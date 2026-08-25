use super::*;

#[test]
fn decode_msix_cap_basic() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    r.write32(bdf, 0x40, 0x8003_0011);
    r.write32(bdf, 0x44, 0x0000_1004);
    r.write32(bdf, 0x48, 0x0000_2004);
    let m = decode_msix_cap(&r, bdf, 0x40).unwrap();
    assert!(m.enabled);
    assert!(!m.function_mask);
    assert_eq!(m.table_size, 4);
    assert_eq!(m.table_bir, 4);
    assert_eq!(m.table_offset, 0x1000);
    assert_eq!(m.pba_bir, 4);
    assert_eq!(m.pba_offset, 0x2000);
}

#[test]
fn msix_table_entry_offset_accepts_decoded_table_range() {
    let m = MsixCap {
        enabled: false,
        function_mask: false,
        table_size: TEST_MSIX_TABLE_ENTRIES,
        table_bir: TEST_MSIX_TABLE_BAR,
        table_offset: TEST_MSIX_TABLE_OFFSET,
        pba_bir: TEST_MSIX_TABLE_BAR,
        pba_offset: 0,
    };

    assert_eq!(msix_table_entry_offset(m, 0), Some(TEST_MSIX_TABLE_OFFSET as u64));
    assert_eq!(
        msix_table_entry_offset(m, TEST_MSIX_LAST_ENTRY),
        Some(TEST_MSIX_TABLE_OFFSET as u64 + (TEST_MSIX_LAST_ENTRY as u64) * MSIX_TABLE_ENTRY_BYTES)
    );
}

#[test]
fn msix_table_entry_offset_rejects_entries_outside_decoded_size() {
    let m = MsixCap {
        enabled: false,
        function_mask: false,
        table_size: TEST_MSIX_TABLE_ENTRIES,
        table_bir: TEST_MSIX_TABLE_BAR,
        table_offset: TEST_MSIX_TABLE_OFFSET,
        pba_bir: TEST_MSIX_TABLE_BAR,
        pba_offset: 0,
    };

    assert_eq!(msix_table_entry_offset(m, m.table_size), None);
    assert_eq!(msix_table_entry_offset(m, m.table_size + 1), None);
}

#[test]
fn capability_walk_and_msix_decode_do_not_write_config_space() {
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    let mut m = HashMap::new();
    m.insert((bdf, 0x04), 0x0010_0000);
    m.insert((bdf, 0x34), 0x0000_0040);
    m.insert((bdf, 0x40), 0xC003_0011);
    m.insert((bdf, 0x44), 0x0000_1004);
    m.insert((bdf, 0x48), 0x0000_2004);
    let r = ReadOnlyReader {
        m,
        writes: std::sync::atomic::AtomicUsize::new(0),
    };

    let caps = capabilities(&r, bdf);
    assert_eq!(caps.find(CAP_ID_MSIX).map(|c| c.cfg_off), Some(0x40));
    let msix = decode_msix_cap(&r, bdf, 0x40).expect("msix cap");
    assert!(msix.enabled);
    assert!(msix.function_mask);
    assert_eq!(r.writes.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn msix_control_value_clears_function_mask_when_enabling() {
    let cur = MSIX_FUNCTION_MASK | 0x03;

    assert_eq!(msix_control_value(cur, true), MSIX_ENABLE | 0x03);
    assert_eq!(
        msix_control_value(MSIX_ENABLE | 0x03, false),
        MSIX_FUNCTION_MASK | 0x03
    );
}

#[test]
fn msix_control_enable_masked_sets_enable_and_function_mask() {
    let cur = 0x03;

    assert_eq!(
        msix_control_enable_masked(cur),
        MSIX_ENABLE | MSIX_FUNCTION_MASK | 0x03
    );
}

#[test]
fn msix_teardown_masks_all_entries_before_disabling_function_and_command() {
    let mut steps = Vec::new();

    emit_msix_teardown_steps(3, |step| steps.push(step));

    assert_eq!(
        steps,
        vec![
            MsixTeardownStep::MaskEntry(0),
            MsixTeardownStep::MaskEntry(1),
            MsixTeardownStep::MaskEntry(2),
            MsixTeardownStep::DisableFunction,
            MsixTeardownStep::DisableMemBusMaster,
        ]
    );
}

#[test]
fn msix_teardown_without_entries_only_drops_command_decode() {
    let mut steps = Vec::new();

    emit_msix_teardown_steps(0, |step| steps.push(step));

    assert_eq!(steps, vec![MsixTeardownStep::DisableMemBusMaster]);
}

#[test]
fn decode_msix_cap_rejects_non_msix() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let bdf = Bdf {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    r.write32(bdf, 0x40, 0x0000_0009);
    assert!(decode_msix_cap(&r, bdf, 0x40).is_none());
}

#[test]
fn empty_bus_returns_nothing() {
    let r = MapReader {
        m: Mutex::new(HashMap::new()),
    };
    let v = enumerate(&r);
    assert!(v.is_empty());
}

