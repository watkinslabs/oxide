// Differential pin against the character database. `data/foldcases.txt` is
// generated beside the table: each line is an input name and the case-folded
// normalized form the generator derived from `unicodedata`/`str.casefold`. If
// the cursor's reordering, ignorable handling, expansion walk, or Hangul
// arithmetic drifts from the source of the table, these cases go red.

use super::fold::enc;
use crate::{casefold_eq, casefold_hash, casefold_into};

static CASES: &str = include_str!("../../data/foldcases.txt");

/// Longest fixture input and its folded form.
const CASE_MAX: usize = 1024;

fn unhex(s: &str, out: &mut [u8; CASE_MAX]) -> usize {
    let b = s.as_bytes();
    assert!(b.len() % 2 == 0 && b.len() / 2 <= CASE_MAX, "malformed fixture field");
    for i in 0..b.len() / 2 {
        let hi = (b[2 * i] as char).to_digit(16).expect("hex") as u8;
        let lo = (b[2 * i + 1] as char).to_digit(16).expect("hex") as u8;
        out[i] = (hi << 4) | lo;
    }
    b.len() / 2
}

#[test]
fn folded_forms_match_the_generated_fixtures() {
    let e = enc();
    let (mut nb, mut wb, mut gb) = ([0u8; CASE_MAX], [0u8; CASE_MAX], [0u8; CASE_MAX]);
    let mut cases = 0;
    for line in CASES.lines() {
        if line.starts_with('#') { continue; }
        let (input, want) = line.split_once(' ').expect("fixture line");
        let n = unhex(input, &mut nb);
        let w = unhex(want, &mut wb);
        let g = casefold_into(&e, &nb[..n], &mut gb).expect("fixture name folds");
        assert_eq!(&gb[..g], &wb[..w], "fold differs for {input}");
        // The folded form is itself a name, and folding is idempotent.
        assert!(casefold_eq(&e, &nb[..n], &wb[..w]).unwrap(), "fold not equal for {input}");
        assert_eq!(casefold_hash(&e, &nb[..n]).unwrap(), casefold_hash(&e, &wb[..w]).unwrap());
        cases += 1;
    }
    assert!(cases > 400, "fixture file lost cases: {cases}");
}
