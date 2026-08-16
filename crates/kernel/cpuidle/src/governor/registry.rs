// The governor list and the per-CPU predictor that goes with whichever one is
// selected. One table: `available_governors` renders it and a write to
// `current_governor` selects out of it.

use alloc::string::String;

use crate::state::IdleState;

use super::input::{Reflection, SelectInput, Selection};
use super::menu::{self, MenuState};
use super::teo::{self, TeoState};

/// Which governor a CPU is running.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Kind { Menu, Teo }

/// One selectable governor.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Governor { pub name: &'static str, pub kind: Kind }

/// Every governor, in listing order.
pub static GOVERNORS: &[Governor] = &[
    Governor { name: "menu", kind: Kind::Menu },
    Governor { name: "teo", kind: Kind::Teo },
];

/// The governor a CPU runs when nothing selected one. Timer-event orientation
/// is the modern default: it needs no duration prediction to be right, only a
/// record of how the last sleeps ended.
pub fn default_governor() -> Governor { GOVERNORS[1] }

/// Resolve a governor by name. # C: O(N_governors)
pub fn by_name(name: &str) -> Option<Governor> {
    let name = name.trim();
    GOVERNORS.iter().copied().find(|gov| gov.name == name)
}

/// Body of `available_governors`. # C: O(N_governors)
pub fn available_names() -> String {
    let mut body = String::new();
    for (index, gov) in GOVERNORS.iter().enumerate() {
        if index > 0 { body.push(' '); }
        body.push_str(gov.name);
    }
    body.push('\n');
    body
}

/// The predictor belonging to whichever governor a CPU runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum State { Menu(MenuState), Teo(TeoState) }

impl State {
    /// A fresh predictor for `kind`. # C: O(1)
    pub fn new(kind: Kind) -> State {
        match kind {
            Kind::Menu => State::Menu(MenuState::default()),
            Kind::Teo => State::Teo(TeoState::default()),
        }
    }

    /// Which governor this predictor belongs to. # C: O(1)
    pub fn kind(&self) -> Kind {
        match self { State::Menu(_) => Kind::Menu, State::Teo(_) => Kind::Teo }
    }

    /// Choose a state. # C: O(N_states)
    pub fn select(&mut self, input: &SelectInput) -> Selection {
        match self {
            State::Menu(menu_state) => menu::select(menu_state, input, input.states.len()),
            State::Teo(teo_state) => teo::select(teo_state, input),
        }
    }

    /// Take the outcome of the sleep that just ended. # C: O(N_states)
    pub fn reflect(&mut self, states: &[IdleState], reflection: &Reflection, tick_ns: u64) {
        match self {
            State::Menu(menu_state) => menu::reflect(menu_state, states, reflection),
            State::Teo(teo_state) => teo::reflect(teo_state, states, reflection, tick_ns),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_governor_resolves_by_its_own_name() {
        for gov in GOVERNORS {
            assert_eq!(by_name(gov.name), Some(*gov));
        }
        assert!(by_name("ladder").is_none());
        assert!(by_name("").is_none());
    }

    #[test]
    fn the_available_list_is_space_separated_and_newline_terminated() {
        assert_eq!(available_names(), "menu teo\n");
    }

    #[test]
    fn the_default_is_a_governor_that_is_actually_listed() {
        assert!(GOVERNORS.contains(&default_governor()));
    }

    #[test]
    fn a_predictor_belongs_to_the_governor_it_was_made_for() {
        assert_eq!(State::new(Kind::Menu).kind(), Kind::Menu);
        assert_eq!(State::new(Kind::Teo).kind(), Kind::Teo);
    }

    #[test]
    fn a_write_with_the_newline_a_shell_adds_still_resolves() {
        assert_eq!(by_name("menu\n").map(|g| g.kind), Some(Kind::Menu));
        assert_eq!(by_name(" teo ").map(|g| g.kind), Some(Kind::Teo));
    }
}
