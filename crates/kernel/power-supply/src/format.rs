// Rendering and parsing of property values. Spaces inside an enum label
// become underscores on the way out, because a uevent variable is
// whitespace-delimited and a daemon splitting `Not charging` on the space
// would read two tokens.

use alloc::string::String;
use alloc::vec::Vec;
use kstrtox::{kstrtol, BASE_AUTO};
use vfs::{KResult, VfsError};

use crate::supply::PropVal;
use crate::uapi::Kind;

/// Space→underscore substitution applied to every rendered enum label.
/// # C: O(n)
pub fn escape_spaces(text: &str) -> String {
    text.chars().map(|c| if c == ' ' { '_' } else { c }).collect()
}

/// Append `text` and the trailing newline every sysfs attribute carries.
/// # C: O(n)
fn line(text: &str) -> Vec<u8> {
    let mut body = String::from(text);
    body.push('\n');
    body.into_bytes()
}

/// Decimal body for an integer attribute. # C: O(1)
fn int_line(value: i32) -> Vec<u8> {
    let mut body = String::new();
    let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{value}\n"));
    body.into_bytes()
}

/// Label at `value` in `table`. Out of range is a driver bug, not a value.
/// # C: O(1)
fn label(table: &'static [&'static str], value: i32) -> KResult<&'static str> {
    let index = usize::try_from(value).map_err(|_| VfsError::Einval)?;
    table.get(index).copied().ok_or(VfsError::Einval)
}

/// Render one property value for a sysfs `show`.
///
/// `available` is the declared-value bitmask for the multi-valued properties;
/// it is ignored by every other kind. `uevent` selects the single-value
/// rendering, because a uevent variable cannot carry a bracketed list.
/// # C: O(N_table)
pub fn render(kind: Kind, value: &PropVal, available: u32, uevent: bool) -> KResult<Vec<u8>> {
    match kind {
        Kind::Int => Ok(int_line(value.as_int()?)),
        Kind::Str => match value {
            PropVal::Str(text) => Ok(line(text)),
            PropVal::Int(_) => Err(VfsError::Einval),
        },
        Kind::Enum(table) => Ok(line(&escape_spaces(label(table, value.as_int()?)?))),
        Kind::Available(table) if uevent => {
            Ok(line(&escape_spaces(label(table, value.as_int()?)?)))
        }
        Kind::Available(table) => render_available(table, available, value.as_int()?),
    }
}

/// Render the declared-value list with the current value bracketed. A current
/// value the supply did not declare is a driver bug and reports `EINVAL`
/// rather than publishing a list that contradicts itself. # C: O(N_table)
fn render_available(table: &'static [&'static str], available: u32, value: i32) -> KResult<Vec<u8>> {
    let current = usize::try_from(value).map_err(|_| VfsError::Einval)?;
    if current >= table.len() { return Err(VfsError::Einval); }
    if available & (1u32 << current.min(u32::BITS as usize - 1)) == 0 { return Err(VfsError::Einval); }
    let mut body = String::new();
    for (index, entry) in table.iter().enumerate() {
        if index >= u32::BITS as usize || available & (1u32 << index) == 0 { continue; }
        if !body.is_empty() { body.push(' '); }
        let escaped = escape_spaces(entry);
        if index == current {
            body.push('[');
            body.push_str(&escaped);
            body.push(']');
        } else {
            body.push_str(&escaped);
        }
    }
    body.push('\n');
    Ok(body.into_bytes())
}

/// Parse a value written to an enum-valued attribute: the exact label, its
/// space-escaped form, or the plain ordinal. # C: O(N_table)
pub fn match_string(table: &[&str], buf: &[u8]) -> KResult<i32> {
    let text = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    for (index, entry) in table.iter().enumerate() {
        if *entry == text || escape_spaces(entry) == text {
            return i32::try_from(index).map_err(|_| VfsError::Einval);
        }
    }
    let value = kstrtol(buf, BASE_AUTO).map_err(|_| VfsError::Einval)?;
    i32::try_from(value).map_err(|_| VfsError::Erange)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::values::{ChargeBehaviour, Status, CHARGE_BEHAVIOUR_TEXT, STATUS_TEXT, TYPE_TEXT};

    #[test]
    fn a_label_with_a_space_is_escaped_so_it_stays_one_token() {
        assert_eq!(escape_spaces("Not charging"), "Not_charging");
        assert_eq!(escape_spaces("Unspecified failure"), "Unspecified_failure");
        assert_eq!(escape_spaces("Li-ion"), "Li-ion");
        assert_eq!(escape_spaces(""), "");
    }

    #[test]
    fn an_enum_renders_its_escaped_label() {
        let body = render(Kind::Enum(STATUS_TEXT), &PropVal::Int(Status::NotCharging as i32), 0, false);
        assert_eq!(body, Ok(b"Not_charging\n".to_vec()));
        let body = render(Kind::Enum(TYPE_TEXT), &PropVal::Int(1), 0, false);
        assert_eq!(body, Ok(b"Battery\n".to_vec()));
    }

    #[test]
    fn an_out_of_range_enum_value_is_einval_not_a_wrong_label() {
        assert_eq!(render(Kind::Enum(STATUS_TEXT), &PropVal::Int(99), 0, false), Err(VfsError::Einval));
        assert_eq!(render(Kind::Enum(STATUS_TEXT), &PropVal::Int(-1), 0, false), Err(VfsError::Einval));
    }

    #[test]
    fn integers_and_strings_render_with_a_trailing_newline() {
        assert_eq!(render(Kind::Int, &PropVal::Int(73), 0, false), Ok(b"73\n".to_vec()));
        assert_eq!(render(Kind::Int, &PropVal::Int(-40), 0, false), Ok(b"-40\n".to_vec()));
        assert_eq!(render(Kind::Str, &PropVal::Str(String::from("OXP-1")), 0, false),
                   Ok(b"OXP-1\n".to_vec()));
        assert_eq!(render(Kind::Int, &PropVal::Str(String::from("x")), 0, false), Err(VfsError::Einval));
        assert_eq!(render(Kind::Str, &PropVal::Int(1), 0, false), Err(VfsError::Einval));
    }

    #[test]
    fn a_multi_valued_property_brackets_the_current_value() {
        let mask = (1 << ChargeBehaviour::Auto as u32)
            | (1 << ChargeBehaviour::InhibitCharge as u32)
            | (1 << ChargeBehaviour::ForceDischarge as u32);
        let body = render(Kind::Available(CHARGE_BEHAVIOUR_TEXT),
                          &PropVal::Int(ChargeBehaviour::InhibitCharge as i32), mask, false);
        assert_eq!(body, Ok(b"auto [inhibit-charge] force-discharge\n".to_vec()));
    }

    #[test]
    fn a_multi_valued_property_collapses_to_one_token_in_a_uevent() {
        let mask = (1 << ChargeBehaviour::Auto as u32) | (1 << ChargeBehaviour::ForceDischarge as u32);
        let body = render(Kind::Available(CHARGE_BEHAVIOUR_TEXT),
                          &PropVal::Int(ChargeBehaviour::ForceDischarge as i32), mask, true);
        assert_eq!(body, Ok(b"force-discharge\n".to_vec()));
    }

    #[test]
    fn a_current_value_outside_the_declared_mask_is_refused() {
        let mask = 1 << ChargeBehaviour::Auto as u32;
        assert_eq!(render(Kind::Available(CHARGE_BEHAVIOUR_TEXT),
                          &PropVal::Int(ChargeBehaviour::ForceDischarge as i32), mask, false),
                   Err(VfsError::Einval));
    }

    #[test]
    fn a_write_matches_the_label_the_escaped_label_or_the_ordinal() {
        assert_eq!(match_string(STATUS_TEXT, b"Charging"), Ok(Status::Charging as i32));
        assert_eq!(match_string(STATUS_TEXT, b"Charging\n"), Ok(Status::Charging as i32));
        assert_eq!(match_string(STATUS_TEXT, b"Not charging"), Ok(Status::NotCharging as i32));
        assert_eq!(match_string(STATUS_TEXT, b"Not_charging\n"), Ok(Status::NotCharging as i32));
        assert_eq!(match_string(STATUS_TEXT, b"4"), Ok(Status::Full as i32));
        assert_eq!(match_string(STATUS_TEXT, b"nonsense"), Err(VfsError::Einval));
    }
}
