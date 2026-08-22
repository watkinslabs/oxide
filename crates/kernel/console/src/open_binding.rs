/// Resolve a VT selector when a file description opens. Selector zero is the
/// foreground alias; every other selector already names a concrete VT.
/// # C: O(1)
pub(crate) fn resolve(selector: u8, foreground: u8) -> u8 {
    if selector == 0 { foreground } else { selector }
}

#[cfg(test)]
mod tests {
    use super::resolve;

    #[test]
    fn foreground_alias_is_bound_once_at_open() {
        let opened = resolve(0, 2);
        let foreground_after_activate = 3;
        assert_eq!(opened, 2);
        assert_ne!(opened, resolve(0, foreground_after_activate));
        assert_eq!(resolve(7, foreground_after_activate), 7);
    }
}
