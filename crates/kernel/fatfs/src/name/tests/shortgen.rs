//! Generating the 8.3 name: what survives folding, what forces a long name,
//! and how the numeric tail finds a name the directory does not already hold.

use alloc::vec::Vec;

use crate::name::codepage::CP437;
use crate::name::flags::{CASE_LOWER_BASE, CASE_LOWER_EXT, SFN_CREATE_WIN95, SFN_CREATE_WINNT,
                         SFN_DEFAULT, SHORT_NAME_LEN};
use crate::name::shortgen::{create, ShortName};

use syscall::errno::Errno;

/// A directory holding no names at all.
fn empty(_: &[u8; SHORT_NAME_LEN]) -> bool { false }

/// A directory holding exactly `taken`.
fn holding(taken: Vec<[u8; SHORT_NAME_LEN]>)
    -> impl FnMut(&[u8; SHORT_NAME_LEN]) -> bool {
    move |name| taken.contains(name)
}

fn units(name: &str) -> Vec<u16> { name.encode_utf16().collect() }

/// Generate with the defaults and no directory in the way.
fn gen(name: &str) -> Result<ShortName, Errno> {
    create(&units(name), &CP437, SFN_DEFAULT, true, 0, &mut empty)
}

fn bytes(name: &str) -> [u8; SHORT_NAME_LEN] { *gen(name).expect("generated").bytes() }

/// A name that already spells itself in 8.3 IS the name — no tail, and no
/// long-name slots to store beside it.
#[test]
fn an_uppercase_eight_three_name_needs_nothing_else() {
    assert_eq!(gen("README.TXT"), Ok(ShortName::Alone { name: *b"README  TXT", lcase: 0 }));
    assert_eq!(gen("MAKEFILE"), Ok(ShortName::Alone { name: *b"MAKEFILE   ", lcase: 0 }));
}

/// The name is folded up, so a lowercase name is 8.3-legal — but the eleven
/// bytes cannot say it was lowercase unless the mount's creation rule records
/// it. That is the whole difference between the two rules.
#[test]
fn a_lowercase_name_needs_slots_under_one_rule_and_not_the_other() {
    let win95 = create(&units("readme.txt"), &CP437, SFN_CREATE_WIN95, true, 0, &mut empty);
    assert_eq!(win95, Ok(ShortName::Aliased { name: *b"README  TXT" }),
               "win95 stores no case bits, so the real name goes in the slots");

    let winnt = create(&units("readme.txt"), &CP437, SFN_CREATE_WINNT, true, 0, &mut empty);
    assert_eq!(winnt, Ok(ShortName::Alone {
        name: *b"README  TXT", lcase: CASE_LOWER_BASE | CASE_LOWER_EXT,
    }), "winnt records it in one bit per half and needs no slots");
}

/// One bit per half cannot record which characters were which, so a name
/// mixed WITHIN a half still needs its long form.
#[test]
fn a_mixed_case_half_still_needs_the_long_form() {
    let mixed = create(&units("ReadMe.txt"), &CP437, SFN_CREATE_WINNT, true, 0, &mut empty);
    assert_eq!(mixed, Ok(ShortName::Aliased { name: *b"README  TXT" }));

    let half = create(&units("README.txt"), &CP437, SFN_CREATE_WINNT, true, 0, &mut empty);
    assert_eq!(half, Ok(ShortName::Alone { name: *b"README  TXT", lcase: CASE_LOWER_EXT }),
               "each half is recorded on its own");
}

/// A name too long, or holding a character the format cannot store, becomes
/// an alias with a numeric tail — and the tail is what makes it unique.
#[test]
fn a_name_that_will_not_fit_gets_a_numeric_tail() {
    assert_eq!(bytes("a very long file name.txt"), *b"AVERYL~1TXT");
    assert_eq!(bytes("archive.tar.gz"), *b"ARCHIV~1GZ ",
               "the LAST dot separates, so the first one is part of the base");
}

/// Spaces and dots are dropped rather than stored; the characters the format
/// reserves become underscores, and either one makes the name an alias.
#[test]
fn dropped_and_replaced_characters_both_force_an_alias() {
    assert_eq!(bytes("my file.txt"), *b"MYFILE~1TXT");
    assert_eq!(bytes("a+b.txt"), *b"A_B~1   TXT");
    assert_eq!(bytes("[x].txt"), *b"_X_~1   TXT");
}

/// A name that is nothing but dots and an extension — a dotfile — has no
/// extension at all: taking the dots as a separator would leave an empty
/// base, and there would be no name.
#[test]
fn a_dotfile_keeps_its_whole_name_as_the_base() {
    assert_eq!(bytes(".profile"), *b"PROFIL~1   ");
    assert_eq!(bytes("...test"), *b"TEST~1     ");
}

/// A character with no byte on the code page is stored as an underscore. The
/// real name is in the slots; the alias only has to be findable.
#[test]
fn a_character_the_page_cannot_store_becomes_an_underscore() {
    assert_eq!(bytes("\u{4e2d}\u{6587}.txt"), *b"__~1    TXT");
}

/// Case folding runs over the code page's own bytes, so it reaches letters
/// the ASCII rule does not — and the folded byte is what gets stored, which
/// is why a small sigma cannot produce a name beginning with the deleted
/// marker's value on this page: it folds to a capital sigma first.
#[test]
fn folding_runs_over_the_pages_bytes_before_anything_is_stored() {
    let name = bytes("\u{3c3}igma.txt");
    assert_eq!(name[0], 0xe4, "capital sigma, not the small one that was asked for");
    assert_eq!(&name[1..], b"IGMA   TXT");
}

/// The tail counts up until it finds a name the directory does not hold.
#[test]
fn the_tail_counts_past_the_names_already_there() {
    let taken = alloc::vec![*b"AVERYL~1TXT", *b"AVERYL~2TXT"];
    let got = create(&units("a very long file name.txt"), &CP437, SFN_DEFAULT, true, 0,
                     &mut holding(taken));
    assert_eq!(got, Ok(ShortName::Aliased { name: *b"AVERYL~3TXT" }));
}

/// Past nine the tail becomes a hashed one rather than continuing to count.
/// Counting is what made a directory of thousands of aliases take quadratic
/// time to gain one more.
#[test]
fn past_nine_the_tail_is_hashed_rather_than_counted() {
    let taken: Vec<[u8; SHORT_NAME_LEN]> = (1..=9u8).map(|n| {
        let mut name = *b"AVERYL~1TXT";
        name[7] = b'0' + n;
        name
    }).collect();
    let got = create(&units("a very long file name.txt"), &CP437, SFN_DEFAULT, true, 0x0002_1234,
                     &mut holding(taken));
    let ShortName::Aliased { name } = got.expect("generated") else { panic!("aliased") };
    assert_eq!(&name[..2], b"AV", "two characters of the base survive");
    assert_eq!(&name[2..6], b"1234", "then the seed's low half in hexadecimal");
    assert_eq!(name[6], b'~');
    assert_eq!(name[7], b'3', "and a digit taken from the seed's high half");
    assert_eq!(&name[8..], b"TXT");
}

/// The hashed tail moves off a collision too, or a full directory would spin.
#[test]
fn the_hashed_tail_steps_off_a_collision() {
    let mut taken: Vec<[u8; SHORT_NAME_LEN]> = (1..=9u8).map(|n| {
        let mut name = *b"AVERYL~1TXT";
        name[7] = b'0' + n;
        name
    }).collect();
    taken.push(*b"AV1234~3TXT");
    let got = create(&units("a very long file name.txt"), &CP437, SFN_DEFAULT, true, 0x0002_1234,
                     &mut holding(taken));
    let ShortName::Aliased { name } = got.expect("generated") else { panic!("aliased") };
    assert_eq!(&name[2..6], b"1229", "stepped down by eleven");
}

/// With the tail switched off, the plain name stands when it is free — and
/// the search runs after all when it is not.
#[test]
fn without_a_tail_the_plain_name_stands_when_it_is_free() {
    let plain = create(&units("a very long file name.txt"), &CP437, SFN_DEFAULT, false, 0,
                       &mut empty);
    assert_eq!(plain, Ok(ShortName::Aliased { name: *b"AVERYLONTXT" }));

    let taken = alloc::vec![*b"AVERYLONTXT"];
    let fallback = create(&units("a very long file name.txt"), &CP437, SFN_DEFAULT, false, 0,
                          &mut holding(taken));
    assert_eq!(fallback, Ok(ShortName::Aliased { name: *b"AVERYL~1TXT" }));
}

/// An 8.3-legal name that is already taken has no alias to fall back on, so
/// the create fails rather than quietly becoming a different name.
#[test]
fn a_legal_name_already_present_is_refused() {
    let taken = alloc::vec![*b"README  TXT"];
    assert_eq!(create(&units("README.TXT"), &CP437, SFN_DEFAULT, true, 0, &mut holding(taken)),
               Err(Errno::Eexist));
}

/// Nothing survives folding, so there is no name to store.
#[test]
fn a_name_of_nothing_but_dropped_characters_is_refused() {
    assert_eq!(gen("..."), Err(Errno::Einval));
    assert_eq!(gen("   "), Err(Errno::Einval));
    assert_eq!(gen(""), Err(Errno::Einval));
}

/// The extension takes at most three characters, and being cut short is what
/// makes the name an alias rather than the name.
#[test]
fn an_extension_longer_than_three_makes_the_name_an_alias() {
    assert_eq!(bytes("archive.tarball"), *b"ARCHIV~1TAR");
    assert_eq!(gen("FILE.TAR"), Ok(ShortName::Alone { name: *b"FILE    TAR", lcase: 0 }));
}
