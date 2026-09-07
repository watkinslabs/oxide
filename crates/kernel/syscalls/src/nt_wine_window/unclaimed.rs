//! Raw win32u ordinals the dispatcher does not admit. The reference syscall
//! dispatcher answers an id outside its table with STATUS_INVALID_SYSTEM_SERVICE
//! and never lets it reach another table; each unknown ordinal is reported once.
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const STATUS_INVALID_SYSTEM_SERVICE: u64 = 0xc000_001c;
/// Table 1 of the generated syscall id space: `0x1000 | index`.
const WIN32U_TABLE: u64 = 0x1000;
const TABLE_MASK: u64 = !0xfff;
const WORDS: usize = 0x1000 / 64;

/// # C: O(1)
pub(crate) const fn is_win32u_ordinal(nr: u64) -> bool { nr & TABLE_MASK == WIN32U_TABLE }

/// The argument index carrying the method code of a multiplexer ordinal. A
/// multiplexer refused by ordinal alone reports nothing about which of its
/// methods the client asked for, which is exactly the fact the report is for.
/// # C: O(1)
pub(crate) const fn method_arg(nr: u64) -> Option<usize> {
    match nr {
        CALL_HWND => Some(1),
        CALL_HWND_PARAM => Some(2),
        CALL_TWO_PARAM => Some(2),
        QUERY_WINDOW => Some(1),
        _ => None,
    }
}

/// The four ordinals that select a request with a code argument. The owning
/// modules declare these numbers too, and the pin test below is what keeps the
/// two agreeing.
const CALL_HWND: u64 = 0x1332;
const CALL_HWND_PARAM: u64 = 0x1336;
const CALL_TWO_PARAM: u64 = 0x133e;
const QUERY_WINDOW: u64 = 0x14df;

/// The method one refused call names, absent for an ordinal that multiplexes
/// nothing. # C: O(1)
pub(crate) fn method_of(nr: u64, args: &[u64]) -> Option<u64> { args.get(method_arg(nr)?).copied() }

pub(crate) struct Seen { words: [AtomicU64; WORDS] }

impl Seen {
    pub(crate) const fn new() -> Self { Self { words: [const { AtomicU64::new(0) }; WORDS] } }
    /// True the first time an ordinal is recorded. # C: O(1)
    pub(crate) fn first(&self, nr: u64) -> bool {
        let index = (nr & 0xfff) as usize;
        let bit = 1u64 << (index % 64);
        self.words[index / 64].fetch_or(bit, Ordering::Relaxed) & bit == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_table_one_ids_are_win32u() {
        assert!(is_win32u_ordinal(0x1332));
        assert!(is_win32u_ordinal(0x1fff));
        assert!(!is_win32u_ordinal(0x0fff));
        assert!(!is_win32u_ordinal(0x2000));
        assert!(!is_win32u_ordinal(0x1332 | (1 << 32)));
    }
    #[test]
    fn a_multiplexer_names_the_method_argument_and_a_plain_ordinal_names_none() {
        let args = [0x11, 0x22, 0x0d, 0x44];
        assert_eq!(method_of(CALL_HWND_PARAM, &args), Some(0x0d));
        assert_eq!(method_of(CALL_HWND, &args), Some(0x22));
        assert_eq!(method_of(CALL_TWO_PARAM, &args), Some(0x0d));
        assert_eq!(method_of(QUERY_WINDOW, &args), Some(0x22));
        assert_eq!(method_of(0x136b, &args), None);
        // A call that carries fewer arguments than the index names nothing.
        assert_eq!(method_of(CALL_HWND_PARAM, &args[..2]), None);
    }

    /// The multiplexer ordinals here must be the ones their owning modules
    /// declare: a trace naming the wrong argument reports a method the client
    /// never sent, which is worse than reporting none.
    #[test]
    fn the_multiplexer_ordinals_are_the_ones_their_owners_declare() {
        use crate::hosted_contracts::*;
        assert_eq!(CALL_HWND, nt_wine_hwnd_call_contract::ORDINAL);
        assert_eq!(CALL_HWND_PARAM, nt_wine_hwnd_param_contract::ORDINAL);
        assert_eq!(CALL_TWO_PARAM, nt_wine_two_param_contract::ORDINAL);
        assert_eq!(QUERY_WINDOW, nt_wine_query_window_contract::ORDINAL);
        assert_eq!(method_arg(CALL_HWND_PARAM), Some(nt_wine_hwnd_param_contract::METHOD_ARG));
    }

    #[test]
    fn each_ordinal_is_reported_once() {
        let seen = Seen::new();
        assert!(seen.first(0x1332));
        assert!(!seen.first(0x1332));
        assert!(seen.first(0x133a));
        assert!(seen.first(0x1000));
        assert!(seen.first(0x1fff));
        assert!(!seen.first(0x1fff));
    }
}
