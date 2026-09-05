//! Pure contracts shared by the PE loader and the native NTDLL adapter.

/// Return the value portion of one environment entry when it is an exact
/// `name=value` match. NTDLL does not treat a second equals sign as part of a
/// valid variable name; this matters for malformed process environments.
pub fn environment_entry_value<'a>(entry: &'a [u16], name: &[u16]) -> Option<&'a [u16]> {
    let equal = entry.iter().position(|&unit| unit == b'=' as u16)?;
    if equal != name.len() || entry.get(equal + 1..)?.iter().any(|&unit| unit == b'=' as u16) { return None; }
    if !entry[..equal].iter().zip(name).all(|(&left, &right)| ascii_fold(left) == ascii_fold(right)) { return None; }
    entry.get(equal + 1..)
}

fn ascii_fold(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 32 } else { unit }
}

#[cfg(test)]
mod tests {
    use super::environment_entry_value;
    use alloc::vec::Vec;
    fn units(value: &str) -> Vec<u16> { value.encode_utf16().collect() }

    #[test]
    fn exact_case_insensitive_name_match_returns_value() {
        let entry = units("PATH=C:\\Windows"); let name = units("path"); let expected = units("C:\\Windows");
        assert_eq!(environment_entry_value(&entry, &name), Some(expected.as_slice()));
    }

    #[test]
    fn malformed_second_equals_and_wrong_name_are_rejected() {
        let entry = units("PATH=C:=C:\\Windows"); let name = units("path");
        assert_eq!(environment_entry_value(&entry, &name), None);
        let entry = units("PATH=C:\\Windows"); let other = units("TEMP");
        assert_eq!(environment_entry_value(&entry, &other), None);
    }
}
