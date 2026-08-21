//! Sole hibernation configuration owner.

use alloc::string::{String, ToString};
use sync::{Spinlock, TaskList as PowerListClass};

use crate::decide::{Error, KResult};
use super::image::Compression;

/// Default memory retained for allocations after image creation.
pub const DEFAULT_RESERVED_SIZE: u64 = 1024 * 1024;
const IMAGE_NUMERATOR: u64 = 2;
const IMAGE_DENOMINATOR: u64 = 5;

/// Resolved name and raw page offset of one configured resume target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeTarget { pub name: String, pub offset: u64 }

/// Complete hibernation settings snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    resume: Option<String>,
    resume_offset: u64,
    noresume: bool,
    nohibernate: bool,
    compression: Compression,
    image_size: u64,
    reserved_size: u64,
}

impl Settings {
    /// Build defaults and apply one ordered boot-option decision. # C: O(target bytes)
    pub fn from_boot(totalram_pages: u64, options: cmdline::hibernate::Options<'_>) -> Self {
        let resume = options.resume.and_then(|bytes| core::str::from_utf8(bytes).ok())
            .filter(|name| !name.is_empty()).map(ToString::to_string);
        let image_size = totalram_pages.saturating_mul(IMAGE_NUMERATOR)
            .checked_div(IMAGE_DENOMINATOR).unwrap_or(0)
            .saturating_mul(super::format::PAGE_SIZE as u64);
        let compression = if options.nocompress { Compression::None } else {
            match options.compressor {
                Some(b"lz4") => Compression::Lz4,
                _ => Compression::Lzo,
            }
        };
        Self { resume, resume_offset: options.resume_offset,
            noresume: options.noresume, nohibernate: options.nohibernate,
            compression, image_size, reserved_size: DEFAULT_RESERVED_SIZE }
    }

    /// Whether write-side hibernation is admitted by boot policy. # C: O(1)
    pub const fn hibernate_enabled(&self) -> bool { !self.nohibernate }
    /// Whether cold-boot resume probing is admitted by boot policy. # C: O(1)
    pub const fn resume_enabled(&self) -> bool { !self.noresume }
    /// Configured cold-boot target, absent when probing is disabled or no
    /// explicit target was supplied. # C: O(target bytes)
    pub fn resume_target(&self) -> Option<ResumeTarget> {
        if !self.resume_enabled() { return None; }
        self.resume.as_ref().map(|name| ResumeTarget {
            name: name.clone(), offset: self.resume_offset,
        })
    }
    /// Write-side target selection. An arbitrary active swap area is not a
    /// durable locator the cold boot can rediscover. # C: O(target bytes)
    pub fn write_target(&self) -> KResult<ResumeTarget> {
        match self.resume.as_ref() {
            Some(name) => Ok(ResumeTarget {
                name: name.clone(), offset: self.resume_offset,
            }),
            None => Err(Error::Nospc),
        }
    }
    /// Configured resume target spelling, or the empty sysfs value. # C: O(1)
    pub fn resume_name(&self) -> &str { self.resume.as_deref().unwrap_or("") }
    /// Configured raw page offset in the resume target. # C: O(1)
    pub const fn resume_offset(&self) -> u64 { self.resume_offset }
    /// Selected image codec. # C: O(1)
    pub const fn compression(&self) -> Compression { self.compression }
    /// Preferred maximum image bytes. # C: O(1)
    pub const fn image_size(&self) -> u64 { self.image_size }
    /// Bytes retained for post-image allocations. # C: O(1)
    pub const fn reserved_size(&self) -> u64 { self.reserved_size }
    /// Parse one future `/sys/power/image_size` write. # C: O(bytes)
    pub fn set_image_size(&mut self, buf: &[u8]) -> KResult<()> {
        self.image_size = parse_size(buf)?; Ok(())
    }
    /// Parse one future `/sys/power/reserved_size` write. # C: O(bytes)
    pub fn set_reserved_size(&mut self, buf: &[u8]) -> KResult<()> {
        self.reserved_size = parse_size(buf)?; Ok(())
    }
    /// Parse one `/sys/power/resume` target and optional `major:minor:offset`.
    /// # C: O(bytes)
    pub fn set_resume(&mut self, buf: &[u8]) -> KResult<()> {
        let value = strip_newline(buf);
        if value.is_empty() || value.contains(&b'\n') { return Err(Error::Inval); }
        let (name_bytes, offset) = parse_resume_target(value)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| Error::Inval)?;
        self.resume = Some(name.to_string());
        if let Some(offset) = offset { self.resume_offset = offset; }
        self.noresume = false;
        Ok(())
    }
    /// Parse one `/sys/power/resume_offset` write. # C: O(bytes)
    pub fn set_resume_offset(&mut self, buf: &[u8]) -> KResult<()> {
        self.resume_offset = parse_size(buf)?; Ok(())
    }
}

static SETTINGS: Spinlock<Option<Settings>, PowerListClass> = Spinlock::new(None);

/// Install settings once boot memory size and the canonical command line are available.
/// # C: O(command line + target bytes)
pub fn init(totalram_pages: u64) {
    let options = cmdline::hibernate::options(cmdline::get());
    *SETTINGS.lock() = Some(Settings::from_boot(totalram_pages, options));
}

/// Snapshot the installed policy. # C: O(target bytes)
pub fn get() -> Option<Settings> { SETTINGS.lock().clone() }

/// Update preferred image bytes for the eventual sysfs adapter. # C: O(bytes)
pub fn set_image_size(buf: &[u8]) -> KResult<()> {
    SETTINGS.lock().as_mut().ok_or(Error::Nodata)?.set_image_size(buf)
}

/// Update reserved bytes for the eventual sysfs adapter. # C: O(bytes)
pub fn set_reserved_size(buf: &[u8]) -> KResult<()> {
    SETTINGS.lock().as_mut().ok_or(Error::Nodata)?.set_reserved_size(buf)
}

/// Update the canonical resume target. # C: O(bytes)
pub fn set_resume(buf: &[u8]) -> KResult<()> {
    SETTINGS.lock().as_mut().ok_or(Error::Nodata)?.set_resume(buf)
}

/// Update the canonical resume offset. # C: O(bytes)
pub fn set_resume_offset(buf: &[u8]) -> KResult<()> {
    SETTINGS.lock().as_mut().ok_or(Error::Nodata)?.set_resume_offset(buf)
}

fn parse_size(buf: &[u8]) -> KResult<u64> {
    let value = strip_newline(buf);
    if value.is_empty() { return Err(Error::Inval); }
    let mut out = 0u64;
    for byte in value {
        if !byte.is_ascii_digit() { return Err(Error::Inval); }
        out = out.checked_mul(10).and_then(|v| v.checked_add((byte - b'0') as u64))
            .ok_or(Error::Inval)?;
    }
    Ok(out)
}

fn strip_newline(buf: &[u8]) -> &[u8] {
    match buf.strip_suffix(b"\n") { Some(value) => value, None => buf }
}

fn parse_resume_target(value: &[u8]) -> KResult<(&[u8], Option<u64>)> {
    let mut separators = value.iter().enumerate().filter_map(|(i, byte)|
        (*byte == b':').then_some(i));
    let Some(first) = separators.next() else { return Ok((value, None)); };
    let Some(second) = separators.next() else { return Ok((value, None)); };
    if separators.next().is_some() { return Err(Error::Inval); }
    let major = &value[..first];
    let minor = &value[first + 1..second];
    let offset = &value[second + 1..];
    if !decimal_component(major) || !decimal_component(minor) {
        return Err(Error::Inval);
    }
    Ok((&value[..second], Some(parse_size(offset)?)))
}

fn decimal_component(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_target_selection_have_one_owner() {
        let settings = Settings::from_boot(100, cmdline::hibernate::options(
            b"resume=/dev/vda2 resume_offset=19"));
        assert_eq!(settings.image_size(), 40 * super::super::format::PAGE_SIZE as u64);
        assert_eq!(settings.reserved_size(), DEFAULT_RESERVED_SIZE);
        assert_eq!(settings.compression(), Compression::Lzo);
        let target = ResumeTarget { name: "/dev/vda2".to_string(), offset: 19 };
        assert_eq!(settings.resume_target(), Some(target.clone()));
        assert_eq!(settings.write_target(), Ok(target));
    }

    #[test]
    fn noresume_and_nohibernate_have_distinct_write_policy() {
        let noresume = Settings::from_boot(0,
            cmdline::hibernate::options(b"resume=/dev/a noresume"));
        assert!(noresume.hibernate_enabled());
        assert!(!noresume.resume_enabled());
        assert_eq!(noresume.resume_target(), None);
        assert!(noresume.write_target().is_ok());

        let disabled = Settings::from_boot(0, cmdline::hibernate::options(b"nohibernate"));
        assert!(!disabled.hibernate_enabled());
        assert!(!disabled.resume_enabled());
    }

    #[test]
    fn no_explicit_target_cannot_produce_a_cold_boot_locator() {
        let settings = Settings::from_boot(0, cmdline::hibernate::Options::default());
        assert_eq!(settings.resume_target(), None);
        assert_eq!(settings.write_target(), Err(Error::Nospc));
    }

    #[test]
    fn byte_tunables_accept_decimal_and_one_optional_newline_only() {
        let mut settings = Settings::from_boot(0, cmdline::hibernate::Options::default());
        settings.set_image_size(b"8192\n").unwrap();
        settings.set_reserved_size(b"0").unwrap();
        assert_eq!((settings.image_size(), settings.reserved_size()), (8192, 0));
        for bad in [b"".as_slice(), b"1\n\n", b"0x20", b"7x",
                    b"18446744073709551616"] {
            assert_eq!(settings.set_image_size(bad), Err(Error::Inval));
        }
        assert_eq!(settings.image_size(), 8192);
    }

    #[test]
    fn resume_name_and_offset_mutate_the_same_settings_owner() {
        let mut settings = Settings::from_boot(0, cmdline::hibernate::Options::default());
        settings.set_resume(b"/dev/vda2\n").unwrap();
        settings.set_resume_offset(b"73").unwrap();
        assert_eq!(settings.resume_name(), "/dev/vda2");
        assert_eq!(settings.resume_offset(), 73);
        assert_eq!(settings.write_target().unwrap(), ResumeTarget {
            name: "/dev/vda2".to_string(), offset: 73,
        });
        assert_eq!(settings.set_resume(b"\n"), Err(Error::Inval));
        assert_eq!(settings.set_resume(b"first\nignored"), Err(Error::Inval));
        assert_eq!(settings.resume_name(), "/dev/vda2");
    }

    #[test]
    fn resume_major_minor_offset_updates_one_atomic_target() {
        let mut settings = Settings::from_boot(0,
            cmdline::hibernate::options(b"resume=/dev/old resume_offset=7"));
        settings.set_resume(b"259:3:4096\n").unwrap();
        assert_eq!(settings.write_target().unwrap(), ResumeTarget {
            name: "259:3".to_string(), offset: 4096,
        });
        let before = settings.clone();
        for bad in [b"259:3:".as_slice(), b"259::4", b"x:3:4",
                    b"259:3:4x", b"259:3:4:5", b"259:3:4\nextra"] {
            assert_eq!(settings.set_resume(bad), Err(Error::Inval));
            assert_eq!(settings, before);
        }
        settings.set_resume(b"259:4").unwrap();
        assert_eq!(settings.write_target().unwrap(), ResumeTarget {
            name: "259:4".to_string(), offset: 4096,
        });
    }

    #[test]
    fn compression_defaults_to_lzo_and_accepts_lz4_or_raw_policy() {
        let lz4 = Settings::from_boot(0,
            cmdline::hibernate::options(b"hibernate.compressor=lz4"));
        assert_eq!(lz4.compression(), Compression::Lz4);
        let raw = Settings::from_boot(0,
            cmdline::hibernate::options(b"hibernate.compressor=lz4 hibernate=nocompress"));
        assert_eq!(raw.compression(), Compression::None);
        let unknown = Settings::from_boot(0,
            cmdline::hibernate::options(b"hibernate.compressor=unknown"));
        assert_eq!(unknown.compression(), Compression::Lzo);
    }
}
