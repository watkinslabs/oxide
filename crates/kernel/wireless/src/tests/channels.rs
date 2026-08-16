// Channel numbering and channel definitions.
//
// The number/frequency mapping is four rules, not one, and the failures are
// silent: a single "base plus five times the number" formula is wrong for
// channel 14, for the lower 5 GHz numbering, for the one 6 GHz channel whose
// frequency sits below its own band base, and for the 60 GHz spacing.

use crate::chan::{channel_to_freq, channel_to_freq_khz, freq_khz_to_band,
                  freq_khz_to_channel, mhz_to_khz, ChanDef, Channel};
use crate::uapi::enums::{Band, ChanWidth};

#[test]
fn the_common_channels_map_to_their_published_frequencies() {
    // 2.4 GHz channels 1 to 13 are on a five-megahertz grid from 2412.
    for (chan, mhz) in [(1, 2412), (6, 2437), (11, 2462), (13, 2472)] {
        assert_eq!(channel_to_freq(chan, Band::Band2Ghz), mhz, "channel {chan}");
        assert_eq!(freq_khz_to_channel(mhz_to_khz(mhz)), chan as u32);
    }
    // Channel 14 is off that grid by twelve megahertz.
    assert_eq!(channel_to_freq(14, Band::Band2Ghz), 2484);
    assert_eq!(freq_khz_to_channel(mhz_to_khz(2484)), 14);
    assert_ne!(channel_to_freq(14, Band::Band2Ghz), 2407 + 14 * 5);

    // 5 GHz.
    for (chan, mhz) in [(36, 5180), (48, 5240), (52, 5260), (100, 5500), (165, 5825)] {
        assert_eq!(channel_to_freq(chan, Band::Band5Ghz), mhz, "channel {chan}");
        assert_eq!(freq_khz_to_channel(mhz_to_khz(mhz)), chan as u32);
    }
    // The lower 5 GHz numbering uses a different base.
    assert_eq!(channel_to_freq(184, Band::Band5Ghz), 4920);
    assert_eq!(channel_to_freq(196, Band::Band5Ghz), 4980);
    assert_eq!(freq_khz_to_channel(mhz_to_khz(4920)), 184);
}

#[test]
fn the_six_gigahertz_band_has_one_channel_below_its_own_base() {
    // Channel 2 is at 5935, below the 5950 base every other channel counts
    // from — the case a single formula gets wrong.
    assert_eq!(channel_to_freq(2, Band::Band6Ghz), 5935);
    assert_eq!(channel_to_freq(1, Band::Band6Ghz), 5955);
    assert_eq!(channel_to_freq(233, Band::Band6Ghz), 7115);
    assert_eq!(freq_khz_to_channel(mhz_to_khz(5935)), 2);
    assert_eq!(freq_khz_to_channel(mhz_to_khz(5955)), 1);
}

#[test]
fn the_sixty_gigahertz_band_steps_by_its_own_channel_width() {
    assert_eq!(channel_to_freq(1, Band::Band60Ghz), 58320);
    assert_eq!(channel_to_freq(2, Band::Band60Ghz), 60480);
    assert_eq!(channel_to_freq(6, Band::Band60Ghz), 69120);
    assert_eq!(channel_to_freq(7, Band::Band60Ghz), 0, "channel 7 is out of range");
    assert_eq!(freq_khz_to_channel(mhz_to_khz(58320)), 1);
    assert_eq!(freq_khz_to_channel(mhz_to_khz(60480)), 2);
}

#[test]
fn a_channel_number_outside_a_band_has_no_frequency() {
    assert_eq!(channel_to_freq(0, Band::Band2Ghz), 0);
    assert_eq!(channel_to_freq(-1, Band::Band2Ghz), 0);
    assert_eq!(channel_to_freq(15, Band::Band2Ghz), 0);
    assert_eq!(channel_to_freq(254, Band::Band6Ghz), 0);
}

#[test]
fn a_frequency_names_its_band() {
    assert_eq!(freq_khz_to_band(mhz_to_khz(2412)), Some(Band::Band2Ghz));
    assert_eq!(freq_khz_to_band(mhz_to_khz(5180)), Some(Band::Band5Ghz));
    assert_eq!(freq_khz_to_band(mhz_to_khz(5955)), Some(Band::Band6Ghz));
    assert_eq!(freq_khz_to_band(mhz_to_khz(58320)), Some(Band::Band60Ghz));
    assert_eq!(freq_khz_to_band(mhz_to_khz(915)), Some(Band::BandS1Ghz));
    assert_eq!(freq_khz_to_band(mhz_to_khz(3000)), None);
}

#[test]
fn the_sub_gigahertz_band_uses_half_megahertz_steps() {
    // Its channels do not sit on the megahertz grid, which is why every
    // frequency in this stack is held in kilohertz.
    assert_eq!(channel_to_freq_khz(1, Band::BandS1Ghz), 902_500);
    assert_eq!(channel_to_freq_khz(3, Band::BandS1Ghz), 903_500);
}

fn chan(mhz: u32) -> Channel { Channel::new(mhz, Band::Band5Ghz, 20) }

#[test]
fn a_narrow_definition_places_its_centre_on_the_channel() {
    let def = ChanDef::new_20(chan(5180));
    assert!(def.is_valid());
    assert_eq!(def.covered_freqs(), alloc::vec![5180]);

    // A twenty-megahertz definition whose stated centre is somewhere else is
    // not a definition of anything.
    let bad = ChanDef::new(chan(5180), ChanWidth::Width20, 5190, 0);
    assert!(!bad.is_valid());
}

#[test]
fn a_wide_definition_must_contain_its_primary_channel() {
    // Channels 36 to 48 make one eighty-megahertz channel centred on 5210.
    for primary in [5180, 5200, 5220, 5240] {
        let def = ChanDef::new(chan(primary), ChanWidth::Width80, 5210, 0);
        assert!(def.is_valid(), "primary {primary} is inside the segment");
        assert_eq!(def.covered_freqs(), alloc::vec![5180, 5200, 5220, 5240]);
    }
    // A primary outside the segment is refused, however plausible the centre.
    let def = ChanDef::new(chan(5260), ChanWidth::Width80, 5210, 0);
    assert!(!def.is_valid());
    // And so is a primary at the segment edge, which is not a channel centre.
    let def = ChanDef::new(chan(5170), ChanWidth::Width80, 5210, 0);
    assert!(!def.is_valid());
}

#[test]
fn a_forty_megahertz_definition_covers_exactly_two_channels() {
    let def = ChanDef::new(chan(5180), ChanWidth::Width40, 5190, 0);
    assert!(def.is_valid());
    assert_eq!(def.covered_freqs(), alloc::vec![5180, 5200]);
    let def = ChanDef::new(chan(5200), ChanWidth::Width40, 5190, 0);
    assert!(def.is_valid());
    assert_eq!(def.covered_freqs(), alloc::vec![5180, 5200]);
}

#[test]
fn only_the_split_width_takes_a_second_segment() {
    // Present when it must not be.
    let def = ChanDef::new(chan(5180), ChanWidth::Width80, 5210, 5530);
    assert!(!def.is_valid());
    // Absent when it must be present.
    let def = ChanDef::new(chan(5180), ChanWidth::Width80P80, 5210, 0);
    assert!(!def.is_valid());
    // Both present and far enough apart.
    let def = ChanDef::new(chan(5180), ChanWidth::Width80P80, 5210, 5530);
    assert!(def.is_valid());
    assert_eq!(def.covered_freqs(),
               alloc::vec![5180, 5200, 5220, 5240, 5500, 5520, 5540, 5560]);
    // Two segments that overlap are one segment, not a split channel.
    let def = ChanDef::new(chan(5180), ChanWidth::Width80P80, 5210, 5250);
    assert!(!def.is_valid());
}

#[test]
fn a_definition_with_no_centre_is_refused() {
    let def = ChanDef::new(chan(5180), ChanWidth::Width80, 0, 0);
    assert!(!def.is_valid());
}

#[test]
fn width_reports_the_spectrum_it_really_occupies() {
    assert_eq!(ChanWidth::Width20.khz(), 20_000);
    assert_eq!(ChanWidth::Width20NoHt.khz(), 20_000);
    assert_eq!(ChanWidth::Width40.khz(), 40_000);
    assert_eq!(ChanWidth::Width80.khz(), 80_000);
    assert_eq!(ChanWidth::Width160.khz(), 160_000);
    assert_eq!(ChanWidth::Width320.khz(), 320_000);
    // The split width occupies two eighty-megahertz segments.
    assert_eq!(ChanWidth::Width80P80.khz(), 160_000);
    assert_eq!(ChanWidth::Width5.khz(), 5_000);
    assert_eq!(ChanWidth::Width10.khz(), 10_000);
}

#[test]
fn identical_definitions_compare_equal_and_differing_ones_do_not() {
    let a = ChanDef::new(chan(5180), ChanWidth::Width80, 5210, 0);
    let b = ChanDef::new(chan(5180), ChanWidth::Width80, 5210, 0);
    assert!(a.is_identical(&b));
    let c = ChanDef::new(chan(5200), ChanWidth::Width80, 5210, 0);
    assert!(!a.is_identical(&c));
    let d = ChanDef::new(chan(5180), ChanWidth::Width40, 5190, 0);
    assert!(!a.is_identical(&d));
}

#[test]
fn channel_predicates_follow_the_flags() {
    use crate::chan::chan_flags;
    use crate::uapi::enums::dfs_state;

    let mut c = chan(5180);
    assert!(c.is_usable());
    assert!(!c.scan_is_passive());
    assert!(c.can_beacon());

    c.flags = chan_flags::NO_IR;
    assert!(c.is_usable(), "receive-only is still usable");
    assert!(c.scan_is_passive());
    assert!(!c.can_beacon());

    c.flags = chan_flags::DISABLED;
    assert!(!c.is_usable());
    assert!(c.scan_is_passive());
    assert!(!c.can_beacon());

    // A radar channel may only be beaconed on once its check has completed.
    c.flags = chan_flags::RADAR;
    c.dfs_state = dfs_state::USABLE;
    assert!(!c.can_beacon());
    c.dfs_state = dfs_state::UNAVAILABLE;
    assert!(!c.can_beacon());
    c.dfs_state = dfs_state::AVAILABLE;
    assert!(c.can_beacon());
}
