// Provenance: the pin default-configuration word every BIOS writes. Reading
// a field at the wrong shift misclassifies a jack, which routes audio to a
// pin nothing is plugged into.

use super::*;

fn cfg(device: u8, port: u8, location: u8, assoc: u8, sequence: u8) -> u32 {
    (u32::from(port) << PORT_CONN_SHIFT)
        | (u32::from(location) << LOCATION_SHIFT)
        | (u32::from(device) << DEVICE_SHIFT)
        | (u32::from(assoc) << ASSOC_SHIFT)
        | u32::from(sequence)
}

#[test]
fn every_field_decodes_at_its_own_shift() {
    let word = cfg(DEV_HP_OUT, PORT_COMPLEX, LOC_FRONT, 2, 3);
    assert_eq!(device(word), DEV_HP_OUT);
    assert_eq!(port_conn(word), PORT_COMPLEX);
    assert_eq!(location(word), LOC_FRONT);
    assert_eq!(association(word), 2);
    assert_eq!(sequence(word), 3);
    assert_eq!(color(0xf << COLOR_SHIFT), 0xf);
    assert_eq!(conn_type(0x1 << CONN_TYPE_SHIFT), 0x1);
    assert_eq!(misc(MISC_NO_PRESENCE << MISC_SHIFT), MISC_NO_PRESENCE as u8);
}

#[test]
fn an_unconnected_pin_is_recognised_and_no_presence_is_separate() {
    assert!(unconnected(cfg(DEV_LINE_OUT, PORT_NONE, 0, 0, 0)));
    assert!(!unconnected(cfg(DEV_LINE_OUT, PORT_COMPLEX, 0, 0, 0)));
    assert!(!no_presence(cfg(DEV_HP_OUT, PORT_COMPLEX, 0, 0, 0)));
    assert!(no_presence(cfg(DEV_HP_OUT, PORT_COMPLEX, 0, 0, 0) | (MISC_NO_PRESENCE << MISC_SHIFT)));
}

#[test]
fn a_fixed_line_out_is_really_a_speaker() {
    assert_eq!(effective_device(cfg(DEV_LINE_OUT, PORT_FIXED, LOC_INTERNAL, 1, 0)), DEV_SPEAKER);
    assert_eq!(effective_device(cfg(DEV_LINE_OUT, PORT_BOTH, LOC_INTERNAL, 1, 0)), DEV_SPEAKER);
    assert_eq!(effective_device(cfg(DEV_LINE_OUT, PORT_COMPLEX, LOC_REAR, 1, 0)), DEV_LINE_OUT);
    // Only a line-out is reinterpreted; a fixed microphone stays a microphone.
    assert_eq!(effective_device(cfg(DEV_MIC_IN, PORT_FIXED, LOC_INTERNAL, 1, 0)), DEV_MIC_IN);
}

#[test]
fn pin_placement_classes_follow_port_and_location() {
    assert_eq!(pin_attr(cfg(DEV_MIC_IN, PORT_NONE, 0, 0, 0)), PinAttr::Unused);
    assert_eq!(pin_attr(cfg(DEV_MIC_IN, PORT_FIXED, LOC_INTERNAL, 0, 0)), PinAttr::Internal);
    assert_eq!(pin_attr(cfg(DEV_MIC_IN, PORT_COMPLEX, LOC_INTERNAL, 0, 0)), PinAttr::Internal);
    assert_eq!(pin_attr(cfg(DEV_MIC_IN, PORT_COMPLEX, LOC_SEPARATE, 0, 0)), PinAttr::Dock);
    assert_eq!(pin_attr(cfg(DEV_MIC_IN, PORT_COMPLEX, LOC_REAR, 0, 0)), PinAttr::Rear);
    assert_eq!(pin_attr(cfg(DEV_MIC_IN, PORT_COMPLEX, LOC_FRONT, 0, 0)), PinAttr::Front);
    assert_eq!(pin_attr(cfg(DEV_MIC_IN, PORT_COMPLEX, LOC_NONE, 0, 0)), PinAttr::Normal);
}

#[test]
fn the_group_sort_key_orders_association_before_sequence() {
    let first = group_sort_key(cfg(DEV_SPEAKER, PORT_FIXED, 0, 1, 3));
    let second = group_sort_key(cfg(DEV_SPEAKER, PORT_FIXED, 0, 2, 0));
    assert!(first < second);
    let same_assoc = group_sort_key(cfg(DEV_SPEAKER, PORT_FIXED, 0, 1, 0));
    assert!(same_assoc < first);
}
