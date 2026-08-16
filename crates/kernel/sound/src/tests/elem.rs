// Provenance: ALSA's control-element contract — numid allocation order,
// numid-zero-means-match-by-id lookup, range clamping per element type, and
// the DB_SCALE TLV word layout `alsamixer` reads to draw a dB scale.

use super::*;

static VALUES: sync::Spinlock<[i64; MAX_ELEM_CHANNELS], sync::TaskList> =
    sync::Spinlock::new([0; MAX_ELEM_CHANNELS]);

fn get(_owner: crate::SoundOwnerKey, _private: u32, out: &mut ElemValues) -> bool {
    *out = *VALUES.lock();
    true
}

fn put(_owner: crate::SoundOwnerKey, _private: u32, values: &ElemValues) -> bool {
    *VALUES.lock() = *values;
    true
}

fn enum_name(_owner: crate::SoundOwnerKey, _private: u32, item: u32, out: &mut [u8; ENUM_NAME_WIDTH]) -> bool {
    let names: [&[u8]; 2] = [b"Mic", b"Line"];
    let Some(name) = names.get(item as usize) else { return false; };
    out[..name.len()].copy_from_slice(name);
    true
}

static OPS: ElemOps = ElemOps { get, put, enum_name };

fn key(raw: u32) -> crate::SoundOwnerKey { crate::SoundOwnerKey::from_raw(raw).unwrap() }

fn volume(name: &[u8]) -> ElemDesc {
    ElemDesc {
        id: ElemId::mixer(name, 0), etype: CTL_ELEM_TYPE_INTEGER,
        access: CTL_ELEM_ACCESS_READWRITE | CTL_ELEM_ACCESS_TLV_READ,
        count: 2, min: 0, max: 87, step: 0, items: 0,
        tlv: Some(DbScale { min_centibel: -6525, step_centibel: 75, mute: true }),
        private: 7, ops: &OPS,
    }
}

#[test]
fn numids_are_allocated_in_registration_order_per_card() {
    let owner = key(0x6001);
    unregister_card(owner);
    assert_eq!(register(owner, volume(b"Master Playback Volume")), 1);
    assert_eq!(register(owner, volume(b"Headphone Playback Volume")), 2);
    assert_eq!(count(owner), 2);
    assert_eq!(with_nth(owner, 0, |numid, _| numid), Some(1));
    assert_eq!(with_nth(owner, 1, |numid, _| numid), Some(2));
    assert_eq!(with_nth(owner, 2, |numid, _| numid), None);
    unregister_card(owner);
    assert_eq!(count(owner), 0);
}

#[test]
fn re_registering_the_same_id_replaces_rather_than_duplicates() {
    let owner = key(0x6002);
    unregister_card(owner);
    let first = register(owner, volume(b"Master Playback Volume"));
    let mut changed = volume(b"Master Playback Volume");
    changed.max = 31;
    let second = register(owner, changed);
    assert_eq!(first, second);
    assert_eq!(count(owner), 1);
    assert_eq!(with_nth(owner, 0, |_, desc| desc.max), Some(31));
    unregister_card(owner);
}

#[test]
fn lookup_falls_back_to_the_full_id_when_numid_is_zero() {
    let owner = key(0x6003);
    unregister_card(owner);
    register(owner, volume(b"Master Playback Volume"));
    register(owner, volume(b"Capture Volume"));
    let by_numid = with_id(owner, 2, &ElemId::mixer(b"", 0), |numid, _| numid);
    assert_eq!(by_numid, Some(2));
    let by_name = with_id(owner, 0, &ElemId::mixer(b"Capture Volume", 0), |numid, _| numid);
    assert_eq!(by_name, Some(2));
    let missing = with_id(owner, 0, &ElemId::mixer(b"No Such Control", 0), |numid, _| numid);
    assert_eq!(missing, None);
    // A different index is a different element even with the same name.
    let other_index = with_id(owner, 0, &ElemId::mixer(b"Capture Volume", 1), |numid, _| numid);
    assert_eq!(other_index, None);
    unregister_card(owner);
}

#[test]
fn elements_are_owner_scoped() {
    let (a, b) = (key(0x6004), key(0x6005));
    unregister_card(a);
    unregister_card(b);
    register(a, volume(b"Master Playback Volume"));
    assert_eq!(count(a), 1);
    assert_eq!(count(b), 0);
    assert_eq!(with_id(b, 1, &ElemId::mixer(b"Master Playback Volume", 0), |numid, _| numid), None);
    unregister_card(a);
}

#[test]
fn range_checks_follow_the_element_type() {
    let integer = volume(b"Master Playback Volume");
    let mut values = [200i64; MAX_ELEM_CHANNELS];
    assert!(!values_in_range(&integer, &values));
    clamp_values(&integer, &mut values);
    assert_eq!(values[0], 87);
    assert_eq!(values[1], 87);
    // Beyond `count` the array is untouched.
    assert_eq!(values[2], 200);
    assert!(values_in_range(&integer, &values));

    let mut boolean = volume(b"Master Playback Switch");
    boolean.etype = CTL_ELEM_TYPE_BOOLEAN;
    let mut on = [5i64; MAX_ELEM_CHANNELS];
    assert!(!values_in_range(&boolean, &on));
    clamp_values(&boolean, &mut on);
    assert_eq!(on[0], 1);

    let mut enumerated = volume(b"Input Source");
    enumerated.etype = CTL_ELEM_TYPE_ENUMERATED;
    enumerated.items = 2;
    enumerated.count = 1;
    let mut item = [9i64; MAX_ELEM_CHANNELS];
    assert!(!values_in_range(&enumerated, &item));
    clamp_values(&enumerated, &mut item);
    assert_eq!(item[0], 1);
}

#[test]
fn db_scale_tlv_carries_the_mute_flag_in_the_step_word() {
    let words = db_scale_words(&DbScale { min_centibel: -6525, step_centibel: 75, mute: true });
    assert_eq!(words[0], CTL_TLVT_DB_SCALE);
    assert_eq!(words[1], 8);
    assert_eq!(words[2] as i32, -6525);
    assert_eq!(words[3], 75 | CTL_TLV_DB_SCALE_MUTE);
    let unmuted = db_scale_words(&DbScale { min_centibel: 0, step_centibel: 50, mute: false });
    assert_eq!(unmuted[3], 50);
}

#[test]
fn driver_ops_round_trip_values_and_name_enumerated_items() {
    let owner = key(0x6006);
    unregister_card(owner);
    register(owner, volume(b"Master Playback Volume"));
    let mut values = [0i64; MAX_ELEM_CHANNELS];
    values[0] = 40;
    values[1] = 41;
    assert!(with_id(owner, 1, &ElemId::mixer(b"", 0), |_, desc| (desc.ops.put)(owner, desc.private, &values)).unwrap());
    let mut read_back = [0i64; MAX_ELEM_CHANNELS];
    assert!(with_id(owner, 1, &ElemId::mixer(b"", 0), |_, desc| (desc.ops.get)(owner, desc.private, &mut read_back)).unwrap());
    assert_eq!(read_back[0], 40);
    assert_eq!(read_back[1], 41);

    let mut name = [0u8; ENUM_NAME_WIDTH];
    assert!(enum_name(owner, 0, 1, &mut name));
    assert_eq!(&name[..4], b"Line");
    assert!(!enum_name(owner, 0, 2, &mut name));
    unregister_card(owner);
}
