// Linux module `.modinfo` parser: NUL-separated `key=value` records.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use elf::{parse_relocatable, Section, SHT_PROGBITS};

/// Module vermagic. Linux stamps the kernel's `UTS_RELEASE` into every module
/// and refuses a mismatch, so this is the SAME string `uname(2)` reports — not
/// a second version number a module could satisfy while targeting a different
/// kernel. The out-of-tree build headers define the same value.
pub const KERNEL_VERMAGIC: &str = syscall::uts::KERNEL_VERMAGIC;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModuleParam {
    pub name: String,
    pub desc: String,
    pub ty:   Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModuleInfo {
    pub name:        Option<String>,
    pub license:     Option<String>,
    pub author:      Vec<String>,
    pub description: Option<String>,
    pub depends:     Vec<String>,
    pub vermagic:    Option<String>,
    pub params:      Vec<ModuleParam>,
    pub aliases:     Vec<String>,
    pub firmware:    Vec<String>,
}

impl ModuleInfo {
    /// # C: O(N_sections + modinfo_bytes)
    pub fn parse_elf(bytes: &[u8]) -> Option<Self> {
        let parsed = parse_relocatable(bytes).ok()?;
        Some(Self::parse_sections(bytes, &parsed.sections))
    }

    /// # C: O(N_sections + modinfo_bytes)
    pub fn parse_sections(bytes: &[u8], sections: &[Section<'_>]) -> Self {
        let mut info = ModuleInfo::default();
        for s in sections {
            if s.name != ".modinfo" || s.sh_type != SHT_PROGBITS { continue; }
            let data = match bytes.get(s.offset as usize .. (s.offset + s.size) as usize) {
                Some(d) => d,
                None => continue,
            };
            info.parse_records(data);
        }
        info
    }

    /// # C: O(1)
    pub fn is_gpl_compatible(&self) -> bool {
        self.license.as_deref().is_some_and(crate::symtab::license_is_gpl)
    }

    /// # C: O(1)
    pub fn vermagic_matches(&self) -> bool {
        self.vermagic.as_deref().is_none_or(|v| v == KERNEL_VERMAGIC)
    }

    fn parse_records(&mut self, data: &[u8]) {
        for rec in data.split(|b| *b == 0) {
            if rec.is_empty() { continue; }
            let Ok(text) = core::str::from_utf8(rec) else { continue };
            let Some((key, val)) = text.split_once('=') else { continue };
            self.record(key, val);
        }
    }

    fn record(&mut self, key: &str, val: &str) {
        match key {
            "name"        => self.name = Some(val.to_string()),
            "license"     => self.license = Some(val.to_string()),
            "author"      => self.author.push(val.to_string()),
            "description" => self.description = Some(val.to_string()),
            "depends"     => push_csv(&mut self.depends, val),
            "vermagic"    => self.vermagic = Some(val.to_string()),
            "parm"        => self.params.push(parse_param(val)),
            "parmtype"    => self.apply_param_type(val),
            "alias"       => self.aliases.push(val.to_string()),
            "firmware"    => self.firmware.push(val.to_string()),
            _ => {}
        }
    }

    fn apply_param_type(&mut self, val: &str) {
        let Some((name, ty)) = val.split_once(':') else { return };
        if let Some(p) = self.params.iter_mut().find(|p| p.name == name) {
            p.ty = Some(ty.to_string());
        } else {
            self.params.push(ModuleParam {
                name: name.to_string(),
                desc: String::new(),
                ty:   Some(ty.to_string()),
            });
        }
    }
}

fn parse_param(val: &str) -> ModuleParam {
    let (name, desc) = val.split_once(':').unwrap_or((val, ""));
    ModuleParam {
        name: name.to_string(),
        desc: desc.to_string(),
        ty:   None,
    }
}

fn push_csv(out: &mut Vec<String>, val: &str) {
    for item in val.split(',') {
        if item.is_empty() { continue; }
        out.push(item.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elf::{Section, SHT_NULL};

    #[test]
    fn parses_records() {
        let _modules = crate::test_serial::claim();
        let mut info = ModuleInfo::default();
        let mut rec = alloc::vec::Vec::new();
        for f in [alloc::format!("name=e1000"), alloc::format!("license=GPL"),
                  alloc::format!("author=A"), alloc::format!("depends=ptp,dca"),
                  alloc::format!("vermagic={KERNEL_VERMAGIC}"),
                  alloc::format!("parm=debug:enable logs"),
                  alloc::format!("parmtype=debug:int")] {
            rec.extend_from_slice(f.as_bytes()); rec.push(0);
        }
        info.parse_records(&rec);
        assert_eq!(info.name.as_deref(), Some("e1000"));
        assert_eq!(info.license.as_deref(), Some("GPL"));
        assert_eq!(info.author, [String::from("A")]);
        assert_eq!(info.depends, [String::from("ptp"), String::from("dca")]);
        assert_eq!(info.vermagic.as_deref(), Some(KERNEL_VERMAGIC));
        assert_eq!(info.params[0].name, "debug");
        assert_eq!(info.params[0].desc, "enable logs");
        assert_eq!(info.params[0].ty.as_deref(), Some("int"));
        assert!(info.is_gpl_compatible());
        assert!(info.vermagic_matches());
    }

    #[test]
    fn parses_modinfo_section() {
        let _modules = crate::test_serial::claim();
        let data = b"name=ahci\0license=Dual BSD/GPL\0description=SATA\0";
        let sec = Section {
            name: ".modinfo", sh_type: SHT_PROGBITS, flags: 0, addr: 0,
            offset: 0, size: data.len() as u64, link: 0, info: 0, addralign: 1, entsize: 0,
        };
        let info = ModuleInfo::parse_sections(data, &[sec]);
        assert_eq!(info.name.as_deref(), Some("ahci"));
        assert_eq!(info.license.as_deref(), Some("Dual BSD/GPL"));
        assert_eq!(info.description.as_deref(), Some("SATA"));
        assert!(info.is_gpl_compatible());
    }

    #[test]
    fn ignores_non_modinfo_sections() {
        let _modules = crate::test_serial::claim();
        let data = b"name=bad\0";
        let sec = Section {
            name: ".strtab", sh_type: SHT_NULL, flags: 0, addr: 0,
            offset: 0, size: data.len() as u64, link: 0, info: 0, addralign: 1, entsize: 0,
        };
        assert_eq!(ModuleInfo::parse_sections(data, &[sec]), ModuleInfo::default());
    }

    // The out-of-tree module build headers must stamp the SAME release the
    // loader checks against; a header that drifts produces modules this kernel
    // rejects with no way to see why from either side.
    #[test]
    fn out_of_tree_build_header_stamps_the_kernel_vermagic() {
        let hdr = include_str!("../../../../kpi/include/generated/utsrelease.h");
        let want = alloc::format!("#define UTS_RELEASE \"{KERNEL_VERMAGIC}\"");
        assert!(hdr.contains(&want), "kpi utsrelease.h must define {want}");
    }

    #[test]
    fn rejects_wrong_vermagic() {
        let _modules = crate::test_serial::claim();
        let mut info = ModuleInfo::default();
        info.parse_records(b"vermagic=9.9.9\0");
        assert!(!info.vermagic_matches());
    }
}
