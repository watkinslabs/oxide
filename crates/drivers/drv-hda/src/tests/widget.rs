// Provenance: HD-Audio widget, pin and amplifier capability layouts, and the
// dB scale a mixer derives from an amplifier's step size and offset.

use super::*;

#[test]
fn widget_type_and_channel_count_decode() {
    assert_eq!(widget_type(0x0 << WCAP_TYPE_SHIFT), WidgetType::AudioOut);
    assert_eq!(widget_type(0x1 << WCAP_TYPE_SHIFT), WidgetType::AudioIn);
    assert_eq!(widget_type(0x2 << WCAP_TYPE_SHIFT), WidgetType::AudioMixer);
    assert_eq!(widget_type(0x3 << WCAP_TYPE_SHIFT), WidgetType::AudioSelector);
    assert_eq!(widget_type(0x4 << WCAP_TYPE_SHIFT), WidgetType::Pin);
    assert_eq!(widget_type(0xf << WCAP_TYPE_SHIFT), WidgetType::Vendor);
    assert_eq!(widget_type(0xe << WCAP_TYPE_SHIFT), WidgetType::Reserved(0xe));

    assert_eq!(widget_channels(0), 1);
    assert_eq!(widget_channels(WCAP_STEREO), 2);
    // One extra pair on top of stereo is four channels.
    assert_eq!(widget_channels(WCAP_STEREO | (1 << WCAP_CHAN_CNT_EXT_SHIFT)), 4);
    assert_eq!(widget_channels(WCAP_STEREO | (3 << WCAP_CHAN_CNT_EXT_SHIFT)), 8);
}

#[test]
fn microphone_bias_follows_the_advertised_capability() {
    let none = 0;
    assert_eq!(default_vref(none), VREF_HIZ);
    let only_50 = (1u32 << VREF_50) << PINCAP_VREF_SHIFT;
    assert_eq!(default_vref(only_50), VREF_50);
    let both = ((1u32 << VREF_50) | (1u32 << VREF_80)) << PINCAP_VREF_SHIFT;
    assert_eq!(default_vref(both), VREF_80);
    assert!(pincap_has_vref(both, VREF_50));
    assert!(!pincap_has_vref(both, VREF_100));
}

#[test]
fn amplifier_capabilities_give_a_db_scale() {
    // 0x4a steps of 0.75 dB, 0 dB at step 0x27, mute supported.
    let caps = amp_caps(0x27 | (0x4a << 8) | (0x02 << 16) | (1 << 31));
    assert_eq!(caps.num_steps, 0x4a);
    assert_eq!(caps.offset, 0x27);
    assert_eq!(caps.step_centibel, 75);
    assert!(caps.mute);
    // Step 0 sits 0x27 steps of 0.75 dB below 0 dB.
    assert_eq!(amp_min_centibel(&caps), -(0x27 * 75));

    let no_mute = amp_caps(0);
    assert!(!no_mute.mute);
    assert_eq!(no_mute.num_steps, 0);
    // A zero step-size field still means 0.25 dB per step, not zero.
    assert_eq!(no_mute.step_centibel, 25);
}

#[test]
fn amp_payloads_select_side_direction_and_index() {
    // Output amp, both channels, unmuted at step 0x20.
    assert_eq!(amp_set_payload(true, 0, true, true, false, 0x20),
               AMP_SET_OUTPUT | AMP_SET_LEFT | AMP_SET_RIGHT | 0x20);
    // Input amp index 2, muted.
    assert_eq!(amp_set_payload(false, 2, true, true, true, 0),
               AMP_SET_INPUT | AMP_SET_LEFT | AMP_SET_RIGHT | (2 << AMP_SET_INDEX_SHIFT) | AMP_MUTE);
    // Gain is seven bits: the mute bit cannot be set by an oversized gain.
    assert_eq!(amp_set_payload(true, 0, false, true, false, 0xff) & AMP_MUTE, 0);

    assert_eq!(amp_get_payload(true, 0, true), AMP_GET_OUTPUT | AMP_GET_LEFT);
    assert_eq!(amp_get_payload(false, 3, false), 3);
    assert_eq!(amp_decode(0x0000_00a0), (true, 0x20));
    assert_eq!(amp_decode(0x0000_0020), (false, 0x20));
}
