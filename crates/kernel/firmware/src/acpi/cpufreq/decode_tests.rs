use super::*;

fn ints(values: &[u64]) -> Vec<AmlField> {
    values.iter().copied().map(AmlField::Int).collect()
}

fn pss(frequency_mhz: u64, latency_us: u64, control: u64, status: u64) -> Vec<AmlField> {
    ints(&[frequency_mhz, 0, latency_us, 0, control, status])
}

fn gas(space: u8, width: u8, address: u64) -> Vec<u8> {
    let mut buffer = alloc::vec![0x82, 12, 0, space, width, 0, 0];
    buffer.extend_from_slice(&address.to_le_bytes());
    buffer.extend_from_slice(&[0x79, 0]);
    buffer
}

#[test]
fn pss_keeps_original_indexes_while_dropping_non_descending_states() {
    let states = decode_pss(&[
        pss(3000, 4, 30, 30), pss(3000, 5, 29, 29), pss(2000, 7, 20, 20),
    ]).expect("PSS");
    assert_eq!(states.len(), 2);
    assert_eq!(states[0].index, 0);
    assert_eq!(states[1].index, 2);
    assert_eq!(states[1].transition_latency_ns, 7_000);
    assert_eq!(frequency_at(&states, 2), Some(2_000_000));
}

#[test]
fn pss_requires_two_distinct_descending_states() {
    assert_eq!(decode_pss(&[pss(1000, 1, 1, 1)]), Err(DecodeError::PssStates));
    assert_eq!(decode_pss(&[pss(1000, 1, 1, 1), pss(2000, 1, 2, 2)]),
               Err(DecodeError::PssStates));
}

#[test]
fn pct_requires_one_supported_matching_address_space() {
    let pct = decode_pct(&[gas(SPACE_SYSTEM_IO as u8, 16, 0x1234), gas(SPACE_SYSTEM_IO as u8, 16, 0x1236)]);
    assert_eq!(pct.expect("PCT").0.width_bits, 16);
    assert_eq!(decode_pct(&[gas(SPACE_SYSTEM_IO as u8, 16, 0x1234), gas(SPACE_FIXED_HARDWARE as u8, 16, 0)]),
               Err(DecodeError::PctMismatch));
    assert_eq!(decode_pct(&[gas(SPACE_SYSTEM_IO as u8, 64, 0x1234), gas(SPACE_SYSTEM_IO as u8, 64, 0x1234)]),
               Err(DecodeError::PctRegister));
}

#[test]
fn ppc_is_an_original_pss_index_not_a_filtered_table_position() {
    assert_eq!(decode_ppc(Some(2), 3), Some(2));
    assert_eq!(decode_ppc(Some(3), 3), None);
    assert_eq!(decode_ppc(None, 3), None);
}

#[test]
fn hardware_readback_uses_the_pss_status_value_not_the_control_value() {
    let states = decode_pss(&[pss(3000, 1, 0x30, 0x13), pss(2000, 1, 0x20, 0x12)])
        .expect("PSS");
    assert_eq!(frequency_for_status(&states, 0x12), Some(2_000_000));
    assert_eq!(frequency_for_status(&states, 0x20), None);
    assert_eq!(frequency_for_msr_status(&states, 0x20), Some(3_000_000));
}

#[test]
fn psd_preserves_domain_size_and_coordination() {
    assert_eq!(decode_psd(&[ints(&[5, 0, 17, COORDINATION_SW_ALL, 4])]),
               Ok(Psd { domain: 17, processors: 4, coordination: Coordination::SoftwareAll }));
    assert_eq!(decode_psd(&[ints(&[5, 0, 17, 0, 4])]), Err(DecodeError::PsdValue));
}
