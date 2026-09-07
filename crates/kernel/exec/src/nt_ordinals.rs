//! Installing the shipped runtime's service numbering at module load.
//!
//! The kernel publishes a service for a name; the shipped module numbers that
//! name with an ordinal fixed at its build. Pairing the two is what lets a
//! stock service stub — which carries a bare ordinal and no namespace tag —
//! reach the service the kernel implements instead of a Linux syscall that
//! happens to have the same number.

use crate::pe_loader::ntdll_catalog;
use syscall::nt::NtService;

/// What one module's numbering contributed. The counts are about service
/// numbers, not export names: the alternate entry points share a number with
/// the service they alias.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Numbering {
    /// Export bodies that decoded as service stubs, aliases included.
    pub decoded: usize,
    /// Distinct service numbers the module carries.
    pub numbers: usize,
    /// Service numbers the installed table now answers.
    pub installed: usize,
    /// Service numbers the kernel publishes no service for. Each is a call the
    /// module can make and this kernel cannot yet serve.
    pub unpublished: usize,
}

/// Longest service name the alias probe buffer must hold.
const MAX_SERVICE_BYTES: usize = 64;

/// The published name a decoded export names. The alternate `Zw` entry points
/// are the same services under a second name, so they resolve through the
/// primary name rather than being read as services the kernel lacks.
/// # C: O(name bytes + catalog)
pub fn service_for_stub_name(name: &[u8]) -> Option<NtService> {
    if let Some(service) = ntdll_catalog::service_for_export(name) { return Some(service); }
    let rest = name.strip_prefix(b"Zw")?;
    let end = rest.len().checked_add(2)?;
    if end > MAX_SERVICE_BYTES { return None; }
    let mut probe = [0u8; MAX_SERVICE_BYTES];
    probe[0] = b'N'; probe[1] = b't';
    probe[2..end].copy_from_slice(rest);
    ntdll_catalog::service_for_export(&probe[..end])
}

/// Pair each decoded service stub with the service the kernel publishes for
/// that name, dropping the names it does not publish.
/// # C: O(services * catalog)
pub fn pairs<'a>(decoded: &'a [pe::ntdll::services::DecodedService<'a>])
    -> impl Iterator<Item = (u32, NtService)> + 'a {
    decoded.iter().filter_map(|service| Some((service.ordinal, service_for_stub_name(service.name)?)))
}

/// One name per service number the kernel publishes no service for, in the
/// module's export order.
/// # C: O(services * catalog)
pub fn unpublished<'a>(decoded: &'a [pe::ntdll::services::DecodedService<'a>]) -> alloc::vec::Vec<&'a [u8]> {
    let mut seen = alloc::vec![false; syscall::nt::ordinals::TABLE_SLOTS];
    let mut out = alloc::vec::Vec::new();
    for service in decoded {
        let Some(number) = syscall::nt::ordinals::runtime_number(service.ordinal) else { continue; };
        if core::mem::replace(&mut seen[number as usize], true) { continue; }
        if service_for_stub_name(service.name).is_none() { out.push(service.name); }
    }
    out
}

/// Distinct service numbers a decoded module carries. # C: O(services)
pub fn numbers(decoded: &[pe::ntdll::services::DecodedService<'_>]) -> usize {
    let mut seen = alloc::vec![false; syscall::nt::ordinals::TABLE_SLOTS];
    let mut count = 0usize;
    for service in decoded {
        let Some(number) = syscall::nt::ordinals::runtime_number(service.ordinal) else { continue; };
        if !core::mem::replace(&mut seen[number as usize], true) { count += 1; }
    }
    count
}

/// Decode a shipped module's service numbering and install it as the raw
/// ordinal route's table.
/// # C: O(export names * name bytes)
pub fn install_from_image(image: &pe::Image<'_>) -> Result<Numbering, pe::Error> {
    let decoded = pe::ntdll::services::decode_all(image)?;
    let installed = syscall::nt::ordinals::install(pairs(&decoded));
    Ok(Numbering { decoded: decoded.len(), numbers: numbers(&decoded), installed, unpublished: unpublished(&decoded).len() })
}

/// The installed numbering is one global table, so every test that touches it
/// runs under this lock rather than racing a sibling's `clear`.
#[cfg(test)]
pub(crate) static TABLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
#[path = "nt_ordinals/tests.rs"]
mod tests;
