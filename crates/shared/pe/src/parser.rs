use alloc::{vec, vec::Vec};
use core::convert::TryInto;

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
/// One `IMAGE_DELAYLOAD_DESCRIPTOR`: eight `DWORD`s.
const DELAY_DESCRIPTOR_BYTES: u32 = 32;
const DELAY_DESCRIPTOR_NAME_OFFSET: usize = 4;
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;
const UNW_FLAG_EHANDLER: u8 = 0x01;
const UNW_FLAG_UHANDLER: u8 = 0x02;
const UNW_FLAG_CHAININFO: u8 = 0x04;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const MAX_UNWIND_CHAIN: usize = 32;
pub const RELAY_DESCRIPTOR_MAGIC: u32 = 0xdeb9_0002;
const DIRECTORY_COUNT: usize = 16;
const PAGE: u32 = 0x1000;
const MAX_FORWARDER_MODULE_NAME: usize = 256;

#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub enum Error { Enoexec, Einval, Unsupported }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct DataDirectory { pub rva: u32, pub size: u32 }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct SectionFlags(pub u32);
impl SectionFlags {
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    pub const MEM_READ: u32 = 0x4000_0000;
    pub const MEM_WRITE: u32 = 0x8000_0000;
    pub const fn contains(self, bits: u32) -> bool { self.0 & bits == bits }
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct Section {
    pub name: [u8; 8], pub virtual_address: u32, pub virtual_size: u32,
    pub raw_offset: u32, pub raw_size: u32, pub characteristics: SectionFlags,
}
#[derive(Debug)] pub struct Import<'a> { pub name: &'a [u8], pub original_first_thunk: u32, pub first_thunk: u32 }
#[derive(Debug, Eq, PartialEq)] pub enum ImportThunk<'a> { Name { hint: u16, name: &'a [u8] }, Ordinal(u16) }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct ExportInfo<'a> { pub name: &'a [u8], pub ordinal_base: u32, pub functions_rva: u32, pub names_rva: u32, pub ordinals_rva: u32, pub function_count: u32, pub name_count: u32 }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub enum ExportTarget<'a> { Rva(u32), Forwarder(&'a [u8]) }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct TlsDirectory { pub start_raw: u64, pub end_raw: u64, pub index: u64, pub callbacks: u64, pub zero_fill: u32, pub characteristics: u32 }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct RuntimeFunction { pub begin_rva: u32, pub end_rva: u32, pub unwind_rva: u32 }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct UnwindCode { pub code_offset: u8, pub unwind_op: u8, pub op_info: u8 }
#[derive(Clone, Debug, Eq, PartialEq)] pub struct UnwindInfo { pub version: u8, pub flags: u8, pub prolog_size: u8, pub code_count: u8, pub frame_register: u8, pub frame_offset: u8, pub codes: Vec<UnwindCode> }
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct UnwindHandler { pub handler_rva: u32, pub data_rva: u32 }
/// x64 register state consumed and produced by one unwind step.
#[derive(Copy, Clone, Debug, Eq, PartialEq)] pub struct UnwindContext {
    pub regs: [u64; 16], pub xmm: [[u64; 2]; 16], pub rip: u64, pub rsp: u64,
}
/// Supplies PE bytes for one dependency name. Search policy stays outside the
/// parser so Linux filesystem paths cannot become implicit DLL search paths.
pub trait ModuleSource<'a> { fn load(&self, name: &[u8]) -> Option<&'a [u8]>; }

pub struct Module<'a> { pub name: &'a [u8], pub image: Image<'a> }

#[derive(Clone)]
pub struct OwnedModule { pub name: Vec<u8>, pub blob: Vec<u8> }

#[derive(Debug)] pub struct Image<'a> {
    pub raw: &'a [u8], pub image_base: u64, pub entry_rva: u32,
    pub section_alignment: u32, pub file_alignment: u32, pub size_of_image: u32,
    pub size_of_headers: u32, pub sections: Vec<Section>,
    pub directories: [DataDirectory; DIRECTORY_COUNT],
}

/// Discover the transitive PE dependency graph in first-seen order. A module
/// is parsed once, cycles are accepted, and missing dependencies fail before
/// any module can be handed to an address-space mapper.
pub fn discover_modules<'a, S: ModuleSource<'a>>(root_name: &'a [u8], root_blob: &'a [u8], source: &S) -> Result<Vec<Module<'a>>, Error> {
    let mut modules = vec![Module { name: root_name, image: parse(root_blob)? }];
    let mut index = 0;
    while index < modules.len() {
        let dependencies = modules[index].image.dependencies()?;
        for dependency in dependencies {
            let resolved = crate::apiset::target(dependency).unwrap_or(dependency);
            if modules.iter().any(|module| crate::loader_name::matches_ascii(module.name, resolved)) { continue; }
            let blob = source.load(resolved).ok_or(Error::Unsupported)?;
            modules.push(Module { name: resolved, image: parse(blob)? });
        }
        index += 1;
    }
    Ok(modules)
}

/// Copy a runtime-supplied dependency graph into owned blobs. This is the
/// handoff form for loaders that discover DLLs incrementally from a runtime
/// filesystem: no borrowed buffer may expire while mapping is in progress.
pub fn discover_owned_modules<'a, S: ModuleSource<'a>>(root_name: &[u8], root_blob: &[u8], source: &S) -> Result<Vec<OwnedModule>, Error> {
    discover_owned_modules_with_builtins(root_name, root_blob, source, |_| false)
}

/// Discover owned dependencies while allowing the caller to identify modules
/// already supplied by a runtime bootstrap (for example native NTDLL stubs).
/// Built-ins are not loaded into the returned graph, but their imports remain
/// resolvable through the caller's fallback resolver. # C: O(total blob bytes)
pub fn discover_owned_modules_with_builtins<'a, S: ModuleSource<'a>, F: Fn(&[u8]) -> bool>(
    root_name: &[u8], root_blob: &[u8], source: &S, is_builtin: F,
) -> Result<Vec<OwnedModule>, Error> {
    let mut modules = vec![OwnedModule { name: root_name.to_vec(), blob: root_blob.to_vec() }];
    let mut index = 0;
    while index < modules.len() {
        let dependencies: Vec<Vec<u8>> = {
            let image = parse(&modules[index].blob)?;
            let imports = image.imports()?;
            let mut names: Vec<Vec<u8>> = imports.iter().map(|import| import.name.to_vec()).collect();
            for import in imports {
                let resolved = crate::apiset::target(import.name).unwrap_or(import.name);
                if is_builtin(resolved) { continue; }
                let dependency = source.load(resolved).ok_or(Error::Unsupported)?;
                let dependency = parse(dependency)?;
                for thunk in image.import_thunks(&import)? {
                    if let Some(name) = dependency.forwarder_dependency(&thunk)? { names.push(name); }
                }
            }
            names
        };
        for dependency in dependencies {
            let resolved = crate::apiset::target(&dependency).unwrap_or(&dependency);
            if is_builtin(resolved) { continue; }
            if modules.iter().any(|module| crate::loader_name::matches_ascii(&module.name, resolved)) { continue; }
            let blob = source.load(resolved).ok_or(Error::Unsupported)?;
            modules.push(OwnedModule { name: resolved.to_vec(), blob: blob.to_vec() });
        }
        index += 1;
    }
    Ok(modules)
}
impl<'a> Image<'a> {
    /// # C: O(N_sections)
    pub fn rva_range(&self, rva: u32, len: u32) -> Result<&'a [u8], Error> {
        let end = rva.checked_add(len).ok_or(Error::Einval)?;
        if end <= self.size_of_headers { return self.raw.get(rva as usize..end as usize).ok_or(Error::Einval); }
        for s in &self.sections {
            let section_end = s.virtual_address.checked_add(s.virtual_size.max(s.raw_size)).ok_or(Error::Einval)?;
            if rva >= s.virtual_address && end <= section_end {
                let inside = rva - s.virtual_address;
                if inside.checked_add(len).filter(|&n| n <= s.raw_size).is_none() { return Err(Error::Einval); }
                let off = s.raw_offset.checked_add(inside).ok_or(Error::Einval)? as usize;
                return self.raw.get(off..off + len as usize).ok_or(Error::Einval);
            }
        }
        Err(Error::Einval)
    }
    /// # C: O(N_sections + SizeOfImage)
    pub fn materialize(&self) -> Result<Vec<u8>, Error> {
        let mut image = vec![0u8; self.size_of_image as usize];
        let headers = self.size_of_headers as usize;
        image[..headers].copy_from_slice(self.raw.get(..headers).ok_or(Error::Einval)?);
        for s in &self.sections {
            let va = s.virtual_address as usize;
            let end = va.checked_add(s.raw_size as usize).ok_or(Error::Einval)?;
            let src_end = (s.raw_offset as usize).checked_add(s.raw_size as usize).ok_or(Error::Einval)?;
            image.get_mut(va..end).ok_or(Error::Einval)?.copy_from_slice(self.raw.get(s.raw_offset as usize..src_end).ok_or(Error::Einval)?);
        }
        Ok(image)
    }
    /// # C: O(import directory + dependency name bytes)
    pub fn imports(&self) -> Result<Vec<Import<'a>>, Error> {
        let d = self.directories[IMAGE_DIRECTORY_ENTRY_IMPORT]; let mut out = Vec::new();
        if d.size == 0 { return Ok(out); }
        let mut at = d.rva; let end = d.rva.checked_add(d.size).ok_or(Error::Einval)?;
        while at < end {
            let bytes = self.rva_range(at, 20)?; let oft = u32(bytes, 0)?; let name_rva = u32(bytes, 12)?; let ft = u32(bytes, 16)?;
            if oft == 0 && name_rva == 0 && ft == 0 { return Ok(out); }
            if name_rva == 0 || ft == 0 { return Err(Error::Einval); }
            out.push(Import { name: self.c_string(name_rva)?, original_first_thunk: oft, first_thunk: ft }); at = at.checked_add(20).ok_or(Error::Einval)?;
        }
        Err(Error::Einval)
    }
    /// Return the dependency module names in descriptor order without
    /// repeating a case-insensitive DLL name.
    pub fn dependencies(&self) -> Result<Vec<&'a [u8]>, Error> {
        let mut out = Vec::new();
        for import in self.imports()? {
            if !out.iter().any(|name: &&[u8]| ascii_eq_ignore_case(name, import.name)) { out.push(import.name); }
        }
        Ok(out)
    }

    /// Return the DLL names named by the delay-load descriptors. A delayed
    /// dependency is bound on first use, so it is absent from the import
    /// directory and still has to reach the module catalog.
    /// # C: O(delay-load directory + dependency name bytes)
    pub fn delay_dependencies(&self) -> Result<Vec<&'a [u8]>, Error> {
        let d = self.directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        let mut out: Vec<&'a [u8]> = Vec::new();
        if d.size == 0 { return Ok(out); }
        let end = d.rva.checked_add(d.size).ok_or(Error::Einval)?;
        let mut at = d.rva;
        while at.checked_add(DELAY_DESCRIPTOR_BYTES).ok_or(Error::Einval)? <= end {
            let bytes = self.rva_range(at, DELAY_DESCRIPTOR_BYTES)?;
            let name_rva = u32(bytes, DELAY_DESCRIPTOR_NAME_OFFSET)?;
            if name_rva == 0 { break; }
            let name = self.c_string(name_rva)?;
            if !out.iter().any(|known: &&[u8]| ascii_eq_ignore_case(known, name)) { out.push(name); }
            at = at.checked_add(DELAY_DESCRIPTOR_BYTES).ok_or(Error::Einval)?;
        }
        Ok(out)
    }

    /// Return import and forwarded-export DLL names in loader order. A
    /// forwarded export is a real dependency even when it is absent from the
    /// import directory; keeping it here makes graph discovery complete before
    /// any image is mapped. # C: O(N_imports + N_export_functions)
    pub fn loader_dependencies(&self) -> Result<Vec<Vec<u8>>, Error> {
        let mut out: Vec<Vec<u8>> = self.dependencies()?.into_iter().map(|name| name.to_vec()).collect();
        let Some(exports) = self.exports()? else { return Ok(out); };
        for index in 0..exports.function_count {
            let ordinal = u16::try_from(exports.ordinal_base.checked_add(index).ok_or(Error::Einval)?).map_err(|_| Error::Einval)?;
            if let Some(name) = self.forwarder_dependency(&ImportThunk::Ordinal(ordinal))? {
                if !out.iter().any(|existing| ascii_eq_ignore_case(existing, &name)) { out.push(name); }
            }
        }
        Ok(out)
    }

    /// Resolve the DLL named by one imported symbol when its export is a
    /// forwarder. Callers must supply an actually imported thunk; EAT data
    /// exports are otherwise indistinguishable from forwarder bytes. # C: O(N_export_names)
    pub fn forwarder_dependency(&self, import: &ImportThunk<'_>) -> Result<Option<Vec<u8>>, Error> {
        let Some(ExportTarget::Forwarder(forwarder)) = self.export_target(import)? else { return Ok(None); };
        let Some(dot) = forwarder.iter().rposition(|byte| *byte == b'.') else { return Err(Error::Einval); };
        if dot == 0 || dot > MAX_FORWARDER_MODULE_NAME { return Err(Error::Einval); }
        let mut name = forwarder[..dot].to_vec();
        if !name.iter().rev().take(4).eq(b"lld.".iter()) { name.extend_from_slice(b".dll"); }
        if name.len() > MAX_FORWARDER_MODULE_NAME { return Err(Error::Einval); }
        Ok(Some(name))
    }
    /// Decode one descriptor's 64-bit import lookup table. # C: O(thunk count + symbol bytes)
    pub fn import_thunks(&self, import: &Import<'a>) -> Result<Vec<ImportThunk<'a>>, Error> {
        let table = if import.original_first_thunk != 0 { import.original_first_thunk } else { import.first_thunk };
        let mut out = Vec::new();
        for index in 0..self.size_of_image / 8 {
            let rva = table.checked_add(index.checked_mul(8).ok_or(Error::Einval)?).ok_or(Error::Einval)?;
            let value = u64(self.rva_range(rva, 8)?, 0)?;
            if value == 0 { return Ok(out); }
            if value & 0x8000_0000_0000_0000 != 0 {
                out.push(ImportThunk::Ordinal((value & 0xffff) as u16));
            } else {
                let name_rva = u32::try_from(value).map_err(|_| Error::Einval)?;
                let hint = u16(self.rva_range(name_rva, 2)?, 0)?;
                out.push(ImportThunk::Name { hint, name: self.c_string(name_rva.checked_add(2).ok_or(Error::Einval)?)? });
            }
        }
        Err(Error::Einval)
    }
    /// # C: O(1)
    pub fn exports(&self) -> Result<Option<ExportInfo<'a>>, Error> {
        let d = self.directories[IMAGE_DIRECTORY_ENTRY_EXPORT]; if d.size == 0 { return Ok(None); }
        let b = self.rva_range(d.rva, 40)?; let name = self.c_string(u32(b, 12)?)?;
        Ok(Some(ExportInfo { name, ordinal_base: u32(b, 16)?, function_count: u32(b, 20)?, name_count: u32(b, 24)?, functions_rva: u32(b, 28)?, names_rva: u32(b, 32)?, ordinals_rva: u32(b, 36)? }))
    }
    /// Locate Wine's PE relay descriptor, if the export directory carries
    /// the descriptor marker immediately before its module-name string.
    /// # C: O(1)
    pub fn relay_descriptor_rva(&self) -> Result<Option<u32>, Error> {
        let Some(_) = self.exports()? else { return Ok(None); };
        let directory = self.directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
        let name_rva = self.rva_range(directory.rva.checked_add(12).ok_or(Error::Einval)?, 4)?;
        let name_rva = u32(name_rva, 0)?;
        let marker_rva = name_rva.checked_sub(8).ok_or(Error::Einval)?;
        let marker = self.rva_range(marker_rva, 8)?;
        if u32(marker, 0)? != RELAY_DESCRIPTOR_MAGIC { return Ok(None); }
        let descriptor_rva = u32(marker, 4)?;
        if descriptor_rva == 0 { return Err(Error::Einval); }
        let descriptor = self.rva_range(descriptor_rva, 8)?;
        if u32(descriptor, 0)? != RELAY_DESCRIPTOR_MAGIC || u32(descriptor, 4)? != 0 {
            return Err(Error::Einval);
        }
        // The x64 descriptor has six pointer-sized fields. Validate the
        // complete record before a loader exposes its address to user code.
        self.rva_range(descriptor_rva, 48)?;
        Ok(Some(descriptor_rva))
    }
    /// Resolve one import to an image RVA or a validated forwarder string.
    /// # C: O(N_export_names)
    pub fn export_target(&self, import: &ImportThunk<'_>) -> Result<Option<ExportTarget<'a>>, Error> {
        let Some(exports) = self.exports()? else { return Ok(None); };
        let index = match import {
            ImportThunk::Ordinal(ordinal) => (*ordinal as u32).checked_sub(exports.ordinal_base),
            ImportThunk::Name { name, .. } => {
                let mut found = None;
                for i in 0..exports.name_count {
                    let name_rva = u32(self.rva_range(exports.names_rva.checked_add(i.checked_mul(4).ok_or(Error::Einval)?).ok_or(Error::Einval)?, 4)?, 0)?;
                    if self.c_string(name_rva)? == *name {
                        found = Some(u16(self.rva_range(exports.ordinals_rva.checked_add(i.checked_mul(2).ok_or(Error::Einval)?).ok_or(Error::Einval)?, 2)?, 0)? as u32);
                        break;
                    }
                }
                found
            }
        };
        let Some(index) = index else { return Ok(None); };
        if index >= exports.function_count { return Ok(None); }
        let rva = u32(self.rva_range(exports.functions_rva.checked_add(index.checked_mul(4).ok_or(Error::Einval)?).ok_or(Error::Einval)?, 4)?, 0)?;
        // A zero EAT slot is an unimplemented/absent export, not the image
        // base. Let the caller report it as unresolved rather than creating
        // a non-executable function pointer to the PE headers.
        if rva == 0 { return Ok(None); }
        let directory = self.directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if rva >= directory.rva && rva < directory.rva.checked_add(directory.size).ok_or(Error::Einval)? {
            return Ok(Some(ExportTarget::Forwarder(self.c_string(rva)?)));
        }
        self.rva_range(rva, 1)?;
        Ok(Some(ExportTarget::Rva(rva)))
    }

    /// Resolve a Wine relay-backed export to the generated x86-64 entry stub.
    /// The ordinary export address table points at the implementation body;
    /// Wine's relay descriptor supplies the ABI adapter that must be entered
    /// by Windows callers. Returns `None` for ordinary PE exports.
    /// # C: O(N_export_names)
    pub fn relay_export_rva(&self, import: &ImportThunk<'_>) -> Result<Option<u32>, Error> {
        let Some(exports) = self.exports()? else { return Ok(None); };
        let Some(index) = self.export_index(exports, import)? else { return Ok(None); };
        let Some(descriptor_rva) = self.relay_descriptor_rva()? else { return Ok(None); };
        let entry_base = u64(self.rva_range(descriptor_rva.checked_add(24).ok_or(Error::Einval)?, 8)?, 0)?;
        let offsets = u64(self.rva_range(descriptor_rva.checked_add(32).ok_or(Error::Einval)?, 8)?, 0)?;
        let image_base = self.image_base;
        let entry_base_rva = entry_base.checked_sub(image_base).ok_or(Error::Einval)?;
        let offsets_rva = offsets.checked_sub(image_base).ok_or(Error::Einval)?;
        let offset_rva = u32::try_from(offsets_rva.checked_add((index as u64).checked_mul(4).ok_or(Error::Einval)?).ok_or(Error::Einval)?).map_err(|_| Error::Einval)?;
        let offset = u32(self.rva_range(offset_rva, 4)?, 0)?;
        if offset == 0 { return Ok(None); }
        let relay = entry_base_rva.checked_add(offset as u64).ok_or(Error::Einval)?;
        let relay = u32::try_from(relay).map_err(|_| Error::Einval)?;
        self.rva_range(relay, 1)?;
        Ok(Some(relay))
    }

    /// Resolve one import against this image's export tables. Forwarders
    /// remain unsupported through this legacy RVA-only accessor.
    pub fn export_rva(&self, import: &ImportThunk<'_>) -> Result<Option<u32>, Error> {
        match self.export_target(import)? { Some(ExportTarget::Rva(rva)) => Ok(Some(rva)), Some(ExportTarget::Forwarder(_)) => Err(Error::Unsupported), None => Ok(None) }
    }

    /// Resolve one non-forwarded export only when its RVA belongs to an
    /// executable PE section. Import and dynamic-procedure callers share this
    /// admission rule so data exports never become callable user addresses.
    /// # C: O(N_sections + N_export_names)
    pub fn executable_export_rva(&self, import: &ImportThunk<'_>) -> Result<Option<u32>, Error> {
        let Some(ExportTarget::Rva(rva)) = self.export_target(import)? else { return Ok(None); };
        let executable = self.sections.iter().any(|section| {
            let end = section.virtual_address.checked_add(section.virtual_size.max(section.raw_size));
            section.characteristics.contains(SectionFlags::MEM_EXECUTE)
                && rva >= section.virtual_address && end.is_some_and(|end| rva < end)
        });
        if executable { Ok(Some(rva)) } else { Err(Error::Unsupported) }
    }

    /// Return the original export-table RVAs in ordinal-index order.
    /// # C: O(N_export_functions)
    pub fn export_rvas(&self) -> Result<Option<alloc::vec::Vec<u32>>, Error> {
        let Some(exports) = self.exports()? else { return Ok(None); };
        let mut rvas = alloc::vec::Vec::with_capacity(exports.function_count as usize);
        for index in 0..exports.function_count {
            let rva = u32(self.rva_range(exports.functions_rva.checked_add(index.checked_mul(4).ok_or(Error::Einval)?).ok_or(Error::Einval)?, 4)?, 0)?;
            rvas.push(rva);
        }
        Ok(Some(rvas))
    }

    /// Return the Wine relay RVA for each ordinal-indexed export. A zero
    /// entry means the export is data, absent, or not covered by the relay
    /// descriptor and must retain its original EAT value.
    /// # C: O(N_export_functions)
    pub fn relay_export_rvas(&self) -> Result<Option<alloc::vec::Vec<u32>>, Error> {
        let Some(exports) = self.exports()? else { return Ok(None); };
        let Some(descriptor_rva) = self.relay_descriptor_rva()? else { return Ok(None); };
        let entry_base = u64(self.rva_range(descriptor_rva.checked_add(24).ok_or(Error::Einval)?, 8)?, 0)?;
        let offsets = u64(self.rva_range(descriptor_rva.checked_add(32).ok_or(Error::Einval)?, 8)?, 0)?;
        let entry_base_rva = entry_base.checked_sub(self.image_base).ok_or(Error::Einval)?;
        let offsets_rva = offsets.checked_sub(self.image_base).ok_or(Error::Einval)?;
        let mut rvas = alloc::vec::Vec::with_capacity(exports.function_count as usize);
        for index in 0..exports.function_count {
            let offset_rva = u32::try_from(offsets_rva.checked_add((index as u64).checked_mul(4).ok_or(Error::Einval)?).ok_or(Error::Einval)?).map_err(|_| Error::Einval)?;
            let offset = u32(self.rva_range(offset_rva, 4)?, 0)?;
            let relay = if offset == 0 { 0 } else { entry_base_rva.checked_add(offset as u64).and_then(|value| u32::try_from(value).ok()).ok_or(Error::Einval)? };
            if relay != 0 { self.rva_range(relay, 1)?; }
            rvas.push(relay);
        }
        Ok(Some(rvas))
    }

    fn export_index(&self, exports: ExportInfo<'_>, import: &ImportThunk<'_>) -> Result<Option<u32>, Error> {
        let index = match import {
            ImportThunk::Ordinal(ordinal) => (*ordinal as u32).checked_sub(exports.ordinal_base),
            ImportThunk::Name { name, .. } => {
                let mut found = None;
                for i in 0..exports.name_count {
                    let name_rva = u32(self.rva_range(exports.names_rva.checked_add(i.checked_mul(4).ok_or(Error::Einval)?).ok_or(Error::Einval)?, 4)?, 0)?;
                    if self.c_string(name_rva)? == *name {
                        found = Some(u16(self.rva_range(exports.ordinals_rva.checked_add(i.checked_mul(2).ok_or(Error::Einval)?).ok_or(Error::Einval)?, 2)?, 0)? as u32);
                        break;
                    }
                }
                found
            }
        };
        let Some(index) = index else { return Ok(None); };
        if index >= exports.function_count { return Ok(None); }
        Ok(Some(index))
    }
    /// # C: O(1)
    pub fn tls(&self) -> Result<Option<TlsDirectory>, Error> {
        let d = self.directories[IMAGE_DIRECTORY_ENTRY_TLS]; if d.size == 0 { return Ok(None); } let b = self.rva_range(d.rva, 40)?;
        Ok(Some(TlsDirectory { start_raw: u64(b, 0)?, end_raw: u64(b, 8)?, index: u64(b, 16)?, callbacks: u64(b, 24)?, zero_fill: u32(b, 32)?, characteristics: u32(b, 36)? }))
    }
    /// Decode the image-relative TLS callback addresses. The callback array
    /// is terminated by a null VA and must stay within this image.
    pub fn tls_callback_rvas(&self) -> Result<Vec<u32>, Error> {
        let Some(tls) = self.tls()? else { return Ok(Vec::new()); };
        if tls.callbacks == 0 { return Ok(Vec::new()); }
        let callback_rva = tls.callbacks.checked_sub(self.image_base).and_then(|rva| u32::try_from(rva).ok()).ok_or(Error::Einval)?;
        let mut out = Vec::new();
        for index in 0..self.size_of_image / 8 {
            let value = u64(self.rva_range(callback_rva.checked_add(index.checked_mul(8).ok_or(Error::Einval)?).ok_or(Error::Einval)?, 8)?, 0)?;
            if value == 0 { return Ok(out); }
            let rva = value.checked_sub(self.image_base).and_then(|rva| u32::try_from(rva).ok()).ok_or(Error::Einval)?;
            self.rva_range(rva, 1)?;
            out.push(rva);
        }
        Err(Error::Einval)
    }
    /// # C: O(exception directory bytes)
    pub fn exception_functions(&self) -> Result<Vec<RuntimeFunction>, Error> {
        let d = self.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION]; if d.size == 0 { return Ok(Vec::new()); } if d.size % 12 != 0 { return Err(Error::Einval); }
        let mut out = Vec::with_capacity((d.size / 12) as usize); let mut previous_end = 0;
        for i in 0..d.size / 12 {
            let b = self.rva_range(d.rva.checked_add(i * 12).ok_or(Error::Einval)?, 12)?;
            let function = RuntimeFunction { begin_rva: u32(b, 0)?, end_rva: u32(b, 4)?, unwind_rva: u32(b, 8)? };
            if function.begin_rva >= function.end_rva || function.begin_rva < previous_end || function.end_rva > self.size_of_image { return Err(Error::Einval); }
            previous_end = function.end_rva; out.push(function);
        }
        for function in &out { self.unwind_chain(*function)?; }
        Ok(out)
    }
    /// Find the runtime function covering an image-relative instruction RVA.
    pub fn exception_function_for(&self, rva: u32) -> Result<Option<RuntimeFunction>, Error> {
        for function in self.exception_functions()? {
            if function.begin_rva >= function.end_rva { return Err(Error::Einval); }
            if rva >= function.begin_rva && rva < function.end_rva { return Ok(Some(function)); }
        }
        Ok(None)
    }
    /// Decode the fixed header and unwind-code array referenced by a runtime function.
    pub fn unwind_info(&self, function: RuntimeFunction) -> Result<UnwindInfo, Error> {
        self.read_unwind_info(function)
    }
    fn read_unwind_info(&self, function: RuntimeFunction) -> Result<UnwindInfo, Error> {
        if function.begin_rva >= function.end_rva || function.end_rva > self.size_of_image || function.unwind_rva & 3 != 0 { return Err(Error::Einval); }
        let header = self.rva_range(function.unwind_rva, 4)?;
        let version = header[0] & 7; let flags = header[0] >> 3;
        if version != 1 { return Err(Error::Unsupported); }
        if flags & !(UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER | UNW_FLAG_CHAININFO) != 0 || flags & UNW_FLAG_CHAININFO != 0 && flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 { return Err(Error::Einval); }
        let code_count = header[2]; let mut codes = Vec::with_capacity(code_count as usize);
        for index in 0..code_count as u32 {
            let bytes = self.rva_range(function.unwind_rva.checked_add(4 + index * 2).ok_or(Error::Einval)?, 2)?;
            codes.push(UnwindCode { code_offset: bytes[0], unwind_op: bytes[1] & 0x0f, op_info: bytes[1] >> 4 });
        }
        Ok(UnwindInfo { version, flags, prolog_size: header[1], code_count, frame_register: header[3] & 0x0f, frame_offset: header[3] >> 4, codes })
    }
    /// Return the language-handler entry and its opaque handler-data start.
    /// The fixed pair is validated without interpreting language-specific data.
    /// # C: O(unwind-code slots)
    pub fn unwind_handler(&self, function: RuntimeFunction) -> Result<Option<UnwindHandler>, Error> {
        let function = self.resolve_unwind_function(function)?;
        let info = self.read_unwind_info(function)?;
        if info.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) == 0 { return Ok(None); }
        let slots = ((info.code_count as u32 + 1) & !1).checked_mul(2).ok_or(Error::Einval)?;
        let handler_at = function.unwind_rva.checked_add(4 + slots).ok_or(Error::Einval)?;
        let handler_rva = u32(self.rva_range(handler_at, 4)?, 0)?;
        self.rva_range(handler_rva, 1)?;
        let data_rva = handler_at.checked_add(4).ok_or(Error::Einval)?;
        if data_rva > self.size_of_image { return Err(Error::Einval); }
        Ok(Some(UnwindHandler { handler_rva, data_rva }))
    }
    fn runtime_function_at(&self, rva: u32) -> Result<RuntimeFunction, Error> {
        if rva & 3 != 0 { return Err(Error::Einval); }
        let b = self.rva_range(rva, 12)?;
        let function = RuntimeFunction { begin_rva: u32(b, 0)?, end_rva: u32(b, 4)?, unwind_rva: u32(b, 8)? };
        if function.begin_rva >= function.end_rva || function.end_rva > self.size_of_image { return Err(Error::Einval); }
        Ok(function)
    }
    /// Follow PE chained runtime-function records to the one carrying the
    /// unwind operations. The bounded walk rejects cycles and malformed
    /// handler data before any caller applies register or stack changes.
    fn resolve_unwind_function(&self, function: RuntimeFunction) -> Result<RuntimeFunction, Error> {
        self.unwind_chain(function)?.last().map(|(function, _)| *function).ok_or(Error::Einval)
    }
    fn unwind_chain(&self, mut function: RuntimeFunction) -> Result<Vec<(RuntimeFunction, UnwindInfo)>, Error> {
        let mut chain = Vec::new(); let mut visited = Vec::new();
        for _ in 0..MAX_UNWIND_CHAIN {
            let info = self.read_unwind_info(function)?;
            chain.push((function, info.clone()));
            if info.flags & UNW_FLAG_CHAININFO == 0 { return Ok(chain); }
            let slots = ((info.code_count as u32 + 1) & !1).checked_mul(2).ok_or(Error::Einval)?;
            let target = function.unwind_rva.checked_add(4 + slots).ok_or(Error::Einval)?;
            if visited.contains(&target) { return Err(Error::Einval); }
            visited.push(target); function = self.runtime_function_at(target)?;
        }
        Err(Error::Einval)
    }
    /// Validate x64 unwind opcode slots and compute their stack allocation.
    /// Register restoration remains the responsibility of the runtime context.
    pub fn unwind_stack_allocation(&self, function: RuntimeFunction) -> Result<u32, Error> {
        let mut bytes = 0u32;
        for (function, info) in self.unwind_chain(function)? {
        let mut slot = 0usize;
        while slot < info.codes.len() {
            let code = info.codes[slot]; slot += 1;
            match code.unwind_op {
                0 => bytes = bytes.checked_add(8).ok_or(Error::Einval)?,
                1 => {
                    let extra = match code.op_info { 0 => 1, 1 => 2, _ => return Err(Error::Einval) };
                    if slot + extra > info.codes.len() { return Err(Error::Einval); }
                    let raw = self.rva_range(function.unwind_rva.checked_add(4 + (slot as u32) * 2).ok_or(Error::Einval)?, (extra * 2) as u32)?;
                    let amount = if extra == 1 { u16::from_le_bytes([raw[0], raw[1]]) as u32 * 8 } else { u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) };
                    bytes = bytes.checked_add(amount).ok_or(Error::Einval)?; slot += extra;
                }
                2 => bytes = bytes.checked_add((code.op_info as u32) * 8 + 8).ok_or(Error::Einval)?,
                3 => if code.op_info != 0 { return Err(Error::Einval); },
                4 => { if slot == info.codes.len() { return Err(Error::Einval); } slot += 1; }
                5 => { if slot + 1 >= info.codes.len() { return Err(Error::Einval); } slot += 2; }
                UWOP_SAVE_XMM128 => { if code.op_info >= 16 || slot == info.codes.len() { return Err(Error::Einval); } slot += 1; }
                UWOP_SAVE_XMM128_FAR => { if code.op_info >= 16 || slot + 1 >= info.codes.len() { return Err(Error::Einval); } slot += 2; }
                10 => bytes = bytes.checked_add(if code.op_info == 0 { 40 } else if code.op_info == 1 { 48 } else { return Err(Error::Einval) }).ok_or(Error::Einval)?,
                _ => return Err(Error::Unsupported),
            }
        }
        }
        Ok(bytes)
    }
    /// Reconstruct the caller context for one x64 frame. The reader owns all
    /// user-memory fault handling; this parser never dereferences `rsp`.
    /// # C: O(unwind-code slots)
    pub fn unwind_x64<F: FnMut(u64) -> Result<u64, Error>>(
        &self, function: Option<RuntimeFunction>, pc_rva: u32, mut context: UnwindContext, mut read: F,
    ) -> Result<UnwindContext, Error> {
        let Some(function) = function else {
            context.rip = read(context.rsp)?;
            context.rsp = context.rsp.checked_add(8).ok_or(Error::Einval)?;
            return Ok(context);
        };
        let chain = self.unwind_chain(function)?;
        for (chain_index, (function, info)) in chain.into_iter().enumerate() {
        let in_prolog = chain_index == 0 && pc_rva >= function.begin_rva && pc_rva < function.begin_rva.saturating_add(info.prolog_size as u32);
        let prolog_offset = if in_prolog { pc_rva - function.begin_rva } else { u32::MAX };
        let mut frame = context.rsp;
        if info.frame_register != 0 {
            if info.frame_register >= 16 { return Err(Error::Einval); }
            frame = context.regs[info.frame_register as usize].checked_sub((info.frame_offset as u64) * 16).ok_or(Error::Einval)?;
        }
        let mut slot = 0usize;
        while slot < info.codes.len() {
            let code = info.codes[slot]; let apply = prolog_offset == u32::MAX || (code.code_offset as u32) <= prolog_offset;
            slot += 1;
            match code.unwind_op {
                0 => { if apply { if code.op_info >= 16 { return Err(Error::Einval); } context.regs[code.op_info as usize] = read(context.rsp)?; context.rsp = context.rsp.checked_add(8).ok_or(Error::Einval)?; } }
                1 => {
                    let extra = match code.op_info { 0 => 1, 1 => 2, _ => return Err(Error::Einval) };
                    if slot + extra > info.codes.len() { return Err(Error::Einval); }
                    let amount = if code.op_info == 0 { (self.unwind_slot(function, slot)? as u32) * 8 } else { self.unwind_double_slot(function, slot)? };
                    if apply { context.rsp = context.rsp.checked_add(amount as u64).ok_or(Error::Einval)?; }
                    slot += extra;
                }
                2 => { if apply { context.rsp = context.rsp.checked_add((code.op_info as u64 + 1) * 8).ok_or(Error::Einval)?; } }
                3 => { if code.op_info != 0 || info.frame_register == 0 { return Err(Error::Einval); } if apply { context.rsp = frame; } }
                4 | 5 => {
                    let extra = if code.unwind_op == 4 { 1 } else { 2 };
                    if slot + extra > info.codes.len() || code.op_info >= 16 { return Err(Error::Einval); }
                    let offset = if extra == 1 { (self.unwind_slot(function, slot)? as u64) * 8 } else { self.unwind_double_slot(function, slot)? as u64 };
                    if apply { context.regs[code.op_info as usize] = read(frame.checked_add(offset).ok_or(Error::Einval)?)?; }
                    slot += extra;
                }
                10 => {
                    if apply {
                        context.rsp = context.rsp.checked_add(if code.op_info == 0 { 0 } else if code.op_info == 1 { 8 } else { return Err(Error::Einval) }).ok_or(Error::Einval)?;
                        context.rip = read(context.rsp)?;
                        context.rsp = read(context.rsp.checked_add(24).ok_or(Error::Einval)?)?;
                    } else if code.op_info > 1 { return Err(Error::Einval); }
                    if info.flags & UNW_FLAG_CHAININFO == 0 { return Ok(context); }
                    return Err(Error::Unsupported);
                }
                UWOP_SAVE_XMM128 | UWOP_SAVE_XMM128_FAR => {
                    let extra = if code.unwind_op == UWOP_SAVE_XMM128 { 1 } else { 2 };
                    if slot + extra > info.codes.len() || code.op_info >= 16 { return Err(Error::Einval); }
                    let offset = if extra == 1 {
                        (self.unwind_slot(function, slot)? as u64).checked_mul(16).ok_or(Error::Einval)?
                    } else { self.unwind_double_slot(function, slot)? as u64 };
                    if apply {
                        let address = frame.checked_add(offset).ok_or(Error::Einval)?;
                        context.xmm[code.op_info as usize] = [read(address)?, read(address.checked_add(8).ok_or(Error::Einval)?)?];
                    }
                    slot += extra;
                }
                _ => return Err(Error::Unsupported),
            }
        }
        if info.flags & UNW_FLAG_CHAININFO != 0 { continue; }
        context.rip = read(context.rsp)?;
        context.rsp = context.rsp.checked_add(8).ok_or(Error::Einval)?;
        }
        Ok(context)
    }
    fn unwind_slot(&self, function: RuntimeFunction, slot: usize) -> Result<u16, Error> {
        let at = function.unwind_rva.checked_add(4 + (slot as u32) * 2).ok_or(Error::Einval)?;
        let bytes = self.rva_range(at, 2)?; Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    fn unwind_double_slot(&self, function: RuntimeFunction, slot: usize) -> Result<u32, Error> {
        let low = self.unwind_slot(function, slot)? as u32; let high = self.unwind_slot(function, slot + 1)? as u32;
        Ok(low | high << 16)
    }
    fn c_string(&self, rva: u32) -> Result<&'a [u8], Error> {
        let mut n = 0u32; while n < self.size_of_image.saturating_sub(rva) { let b = self.rva_range(rva + n, 1)?; if b[0] == 0 { return self.rva_range(rva, n); } n += 1; } Err(Error::Einval)
    }
}

/// # C: O(file size)
pub fn parse(raw: &[u8]) -> Result<Image<'_>, Error> {
    if raw.len() < 64 || &raw[..2] != b"MZ" { return Err(Error::Enoexec); }
    let pe = u32(raw, 0x3c)? as usize;
    if raw.get(pe..pe.checked_add(4).ok_or(Error::Einval)?) != Some(b"PE\0\0") { return Err(Error::Enoexec); }
    let coff = pe + 4;
    if u16(raw, coff)? != IMAGE_FILE_MACHINE_AMD64 { return Err(Error::Enoexec); }
    let nsec = u16(raw, coff + 2)? as usize; let opt_size = u16(raw, coff + 16)? as usize;
    if nsec == 0 || nsec > 96 { return Err(Error::Einval); }
    let opt = coff.checked_add(20).ok_or(Error::Einval)?; let opt_end = opt.checked_add(opt_size).ok_or(Error::Einval)?;
    if opt_end > raw.len() || opt_size < 112 || u16(raw, opt)? != IMAGE_NT_OPTIONAL_HDR64_MAGIC { return Err(Error::Enoexec); }
    let image_base = u64(raw, opt + 24)?; let section_alignment = u32(raw, opt + 32)?; let file_alignment = u32(raw, opt + 36)?;
    let size_of_image = u32(raw, opt + 56)?; let size_of_headers = u32(raw, opt + 60)?;
    if !valid_alignment(section_alignment, PAGE) || !valid_alignment(file_alignment, 1) || file_alignment > section_alignment || size_of_image == 0 || size_of_image % section_alignment != 0 || size_of_headers == 0 || size_of_headers > size_of_image || size_of_headers as usize > raw.len() { return Err(Error::Einval); }
    let ndir = (u32(raw, opt + 108)? as usize).min(DIRECTORY_COUNT); let dir_end = opt.checked_add(112 + ndir * 8).ok_or(Error::Einval)?;
    if dir_end > opt_end { return Err(Error::Einval); }
    let mut directories = [DataDirectory { rva: 0, size: 0 }; DIRECTORY_COUNT];
    for (i, d) in directories.iter_mut().enumerate().take(ndir) { d.rva = u32(raw, opt + 112 + i * 8)?; d.size = u32(raw, opt + 116 + i * 8)?; if d.size != 0 { range_in_image(d.rva, d.size, size_of_image)?; } }
    let table = opt_end; let table_end = table.checked_add(nsec * 40).ok_or(Error::Einval)?;
    if table_end > raw.len() || table_end as u32 > size_of_headers { return Err(Error::Einval); }
    let mut sections: Vec<Section> = Vec::with_capacity(nsec); let mut max_end = size_of_headers;
    for i in 0..nsec {
        let p = table + i * 40; let mut name = [0u8; 8]; name.copy_from_slice(&raw[p..p + 8]);
        let virtual_size = u32(raw, p + 8)?; let virtual_address = u32(raw, p + 12)?; let raw_size = u32(raw, p + 16)?; let raw_offset = u32(raw, p + 20)?; let characteristics = SectionFlags(u32(raw, p + 36)?);
        if raw_size != 0 { raw_offset.checked_add(raw_size).filter(|&e| e as usize <= raw.len()).ok_or(Error::Einval)?; }
        let span = virtual_size.max(raw_size); let end = virtual_address.checked_add(align_up(span, section_alignment)).ok_or(Error::Einval)?;
        if virtual_address < size_of_headers || end > size_of_image || virtual_address % section_alignment != 0 { return Err(Error::Einval); }
        for prior in &sections {
            let prior_end = prior.virtual_address.checked_add(align_up(prior.virtual_size.max(prior.raw_size), section_alignment)).ok_or(Error::Einval)?;
            if virtual_address < prior_end && prior.virtual_address < end { return Err(Error::Einval); }
        }
        max_end = max_end.max(end); sections.push(Section { name, virtual_address, virtual_size, raw_offset, raw_size, characteristics });
    }
    if max_end > size_of_image { return Err(Error::Einval); }
    let entry_rva = u32(raw, opt + 16)?; range_in_image(entry_rva, 1, size_of_image)?;
    if entry_rva >= size_of_headers && !sections.iter().any(|s| {
        let end = s.virtual_address.saturating_add(s.virtual_size.max(s.raw_size));
        entry_rva >= s.virtual_address && entry_rva < end
    }) { return Err(Error::Einval); }
    Ok(Image { raw, image_base, entry_rva, section_alignment, file_alignment, size_of_image, size_of_headers, sections, directories })
}

/// # C: O(relocation bytes)
pub fn apply_relocations(image: &mut [u8], parsed: &Image<'_>, new_base: u64) -> Result<(), Error> {
    if new_base == parsed.image_base { return Ok(()); }
    if image.len() != parsed.size_of_image as usize { return Err(Error::Einval); }
    let d = parsed.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC]; let end = d.rva.checked_add(d.size).ok_or(Error::Einval)? as usize; let mut at = d.rva as usize;
    if end > image.len() { return Err(Error::Einval); } let delta = new_base.wrapping_sub(parsed.image_base);
    while at < end { if end - at < 8 { return Err(Error::Einval); } let page = read32(image, at)?; let block = read32(image, at + 4)? as usize; if block < 8 || block % 2 != 0 || at.checked_add(block).filter(|&e| e <= end).is_none() { return Err(Error::Einval); }
        for i in 0..(block - 8) / 2 { let item = read16(image, at + 8 + i * 2)?; let target = page.checked_add((item & 0xfff) as u32).ok_or(Error::Einval)? as usize; match item >> 12 { IMAGE_REL_BASED_ABSOLUTE => {}, IMAGE_REL_BASED_DIR64 => { let value = read64(image, target)?; write64(image, target, value.wrapping_add(delta))?; }, _ => return Err(Error::Unsupported) } } at += block;
    }
    Ok(())
}
fn valid_alignment(v: u32, min: u32) -> bool { v >= min && v.is_power_of_two() }
fn align_up(v: u32, a: u32) -> u32 { v.saturating_add(a - 1) & !(a - 1) }
fn range_in_image(rva: u32, len: u32, size: u32) -> Result<(), Error> { if rva.checked_add(len).filter(|&e| e <= size).is_some() { Ok(()) } else { Err(Error::Einval) } }
fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool { left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase()) }
fn u16(b: &[u8], o: usize) -> Result<u16, Error> { Ok(u16::from_le_bytes(b.get(o..o + 2).ok_or(Error::Einval)?.try_into().map_err(|_| Error::Einval)?)) }
fn u32(b: &[u8], o: usize) -> Result<u32, Error> { Ok(u32::from_le_bytes(b.get(o..o + 4).ok_or(Error::Einval)?.try_into().map_err(|_| Error::Einval)?)) }
fn u64(b: &[u8], o: usize) -> Result<u64, Error> { Ok(u64::from_le_bytes(b.get(o..o + 8).ok_or(Error::Einval)?.try_into().map_err(|_| Error::Einval)?)) }
fn read16(b: &[u8], o: usize) -> Result<u16, Error> { u16(b, o) }
fn read32(b: &[u8], o: usize) -> Result<u32, Error> { u32(b, o) }
fn read64(b: &[u8], o: usize) -> Result<u64, Error> { u64(b, o) }
fn write64(b: &mut [u8], o: usize, v: u64) -> Result<(), Error> { b.get_mut(o..o + 8).ok_or(Error::Einval)?.copy_from_slice(&v.to_le_bytes()); Ok(()) }
