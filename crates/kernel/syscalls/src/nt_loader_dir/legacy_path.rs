//! The process default DLL load path: what the loader searches when neither
//! the request nor `LdrSetDefaultDllDirectories` names a search set. Reads the
//! image directory, current directory and `PATH` from the process parameters
//! the way the reference builds its default load path at process start.
use alloc::vec::Vec;

const PROCESS_PARAMETERS_OFFSET: u64 = super::PEB_IMAGE_BASE_OFFSET + 0x10;
const CURRENT_DIRECTORY_OFFSET: u64 = 0x38;
const IMAGE_PATH_NAME_OFFSET: u64 = 0x60;
const ENVIRONMENT_OFFSET: u64 = 0x80;
/// Bound on the environment block scanned for `PATH`.
const ENVIRONMENT_BYTES_MAX: usize = 64 * 1024;
const PATH_PREFIX: &[u8] = b"P\0A\0T\0H\0=\0";

/// Ordered legacy directories for the current process, UTF-16LE bytes.
/// # C: O(len(environment))
pub(super) fn directories(cur: &sched::Task) -> Vec<Vec<u8>> {
    let parameters = cur.nt_teb().checked_add(super::TEB_PEB_OFFSET).and_then(super::read_u64_checked)
        .and_then(|peb| peb.checked_add(PROCESS_PARAMETERS_OFFSET)).and_then(super::read_u64_checked).unwrap_or(0);
    let unicode_at = |offset: u64| parameters.checked_add(offset).filter(|_| parameters != 0).and_then(super::read_unicode).unwrap_or_default();
    let image = unicode_at(IMAGE_PATH_NAME_OFFSET);
    let current = unicode_at(CURRENT_DIRECTORY_OFFSET);
    let dll_directory = cur.thread_group.nt_dll_directory.lock().clone();
    let path = parameters.checked_add(ENVIRONMENT_OFFSET).filter(|_| parameters != 0)
        .and_then(super::read_u64_checked).and_then(environment_path).unwrap_or_default();
    crate::nt_loader_dir_policy::legacy_search_order(super::directory_of(&image),
        (!dll_directory.is_empty()).then_some(dll_directory.as_slice()), trim_trailing_separator(&current), &path)
}

/// `PATH=` value out of a double-NUL-terminated UTF-16 environment block.
fn environment_path(block: u64) -> Option<Vec<u8>> {
    if block == 0 { return None; }
    let mut at = 0usize;
    while at < ENVIRONMENT_BYTES_MAX {
        let entry = read_wide_entry(block.checked_add(at as u64)?, ENVIRONMENT_BYTES_MAX - at)?;
        if entry.is_empty() { return None; }
        at += entry.len() + 2;
        if entry.len() >= PATH_PREFIX.len() && entry[..PATH_PREFIX.len()].eq_ignore_ascii_case(PATH_PREFIX) {
            return Some(entry[PATH_PREFIX.len()..].to_vec());
        }
    }
    None
}

/// One NUL-terminated UTF-16 entry (without its terminator), bounded.
fn read_wide_entry(address: u64, limit: usize) -> Option<Vec<u8>> {
    let mut value = Vec::new();
    let mut unit = [0u8; 2];
    while value.len() + 2 <= limit {
        uaccess::copy_from_user(&mut unit, address.checked_add(value.len() as u64)?).ok()?;
        if unit == [0, 0] { return Some(value); }
        value.extend_from_slice(&unit);
    }
    None
}

fn trim_trailing_separator(dir: &[u8]) -> &[u8] {
    if dir.len() > 6 && (dir[dir.len() - 2] == b'\\' || dir[dir.len() - 2] == b'/') && dir[dir.len() - 1] == 0 { &dir[..dir.len() - 2] } else { dir }
}
