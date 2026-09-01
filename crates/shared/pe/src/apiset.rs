//! The process API-set contracts shared by the PE graph and NT environment.

use core::cmp::min;

const CONTRACTS: [(&[u8], &[u8]); 4] = [
    (b"api-ms-win-core-synch-l1-2-0", b"kernelbase.dll"),
    (b"api-ms-win-core-file-l1-2-0", b"kernelbase.dll"),
    (b"api-ms-win-core-libraryloader-l1-2-0", b"kernelbase.dll"),
    (b"ext-ms-win-ntuser-window-l1-1-0", b"user32.dll"),
];

/// Return the built-in contract records used for a fresh NT process.
pub fn entries() -> &'static [(&'static [u8], &'static [u8])] { &CONTRACTS }

/// Resolve a DLL-form API-set contract to its host DLL, if it is in the
/// process schema. The caller retains ownership of the input name.
pub fn target(name: &[u8]) -> Option<&'static [u8]> {
    let stem_len = if name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case(b".dll") { name.len() - 4 } else { name.len() };
    let stem = &name[..min(stem_len, name.len())];
    CONTRACTS.iter().find(|(contract, _)| contract.eq_ignore_ascii_case(stem)).map(|(_, host)| *host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_contract_names_with_or_without_dll_suffix() {
        assert_eq!(target(b"API-MS-WIN-CORE-SYNCH-L1-2-0.dll"), Some(b"kernelbase.dll".as_slice()));
        assert_eq!(target(b"ext-ms-win-missing-l1-1-0.dll"), None);
    }
}
