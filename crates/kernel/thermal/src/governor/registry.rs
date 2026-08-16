// The governor list. One table: a zone selects out of it by name, and
// `available_policies` renders it. A second list somewhere else is how a
// policy accepted by a write ends up naming a governor the zone cannot run.

use alloc::string::String;

use super::bang_bang::BANG_BANG;
use super::fair_share::FAIR_SHARE;
use super::input::Governor;
use super::step_wise::STEP_WISE;
use super::user_space::USER_SPACE;

/// Every governor a zone may select, in listing order.
pub static GOVERNORS: &[&Governor] = &[&STEP_WISE, &BANG_BANG, &FAIR_SHARE, &USER_SPACE];

/// The governor a zone gets when its provider names none. Stepping is the
/// safe default: it works with a device of any depth, where the on/off
/// governor would drive a multi-state device to its shallowest useful state.
/// # C: O(1)
pub fn default_governor() -> &'static Governor { &STEP_WISE }

/// Resolve a governor by name, matching without regard to case and ignoring
/// the whitespace a shell redirect appends. # C: O(N_governors)
pub fn by_name(name: &str) -> Option<&'static Governor> {
    let name = name.trim();
    GOVERNORS.iter().copied().find(|gov| gov.name.eq_ignore_ascii_case(name))
}

/// Body of `available_policies`: every name, each followed by a space, then
/// the newline. # C: O(N_governors)
pub fn available_names() -> String {
    let mut body = String::new();
    for gov in GOVERNORS {
        body.push_str(gov.name);
        body.push(' ');
    }
    body.push('\n');
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_governor_resolves_by_its_own_name() {
        for gov in GOVERNORS {
            let found = by_name(gov.name).expect("listed governor must resolve");
            assert_eq!(found.name, gov.name);
        }
    }

    #[test]
    fn a_write_with_a_trailing_newline_or_odd_case_still_resolves() {
        assert_eq!(by_name("step_wise\n").map(|g| g.name), Some("step_wise"));
        assert_eq!(by_name(" bang_bang ").map(|g| g.name), Some("bang_bang"));
        assert_eq!(by_name("USER_SPACE").map(|g| g.name), Some("user_space"));
        assert!(by_name("ondemand").is_none());
        assert!(by_name("").is_none());
    }

    #[test]
    fn the_available_list_is_space_separated_and_newline_terminated() {
        let body = available_names();
        assert_eq!(body, "step_wise bang_bang fair_share user_space \n");
        assert!(body.ends_with('\n'));
    }

    #[test]
    fn the_default_is_a_governor_that_is_actually_listed() {
        assert!(GOVERNORS.iter().any(|g| g.name == default_governor().name));
    }

    #[test]
    fn only_the_userspace_governor_publishes_crossings_instead_of_cooling() {
        let publishers: alloc::vec::Vec<&str> = GOVERNORS.iter()
            .filter(|g| g.publishes_crossings).map(|g| g.name).collect();
        assert_eq!(publishers, alloc::vec!["user_space"]);
    }
}
