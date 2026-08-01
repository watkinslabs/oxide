// ELF and note constants the core-file format fixes. ABI numbers only: no policy.

/// `e_ident` magic.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

pub const EI_CLASS:   usize = 4;
pub const EI_DATA:    usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI:   usize = 7;
pub const EI_NIDENT:  usize = 16;

pub const ELFCLASS64:    u8 = 2;
pub const ELFDATA2LSB:   u8 = 1;
pub const EV_CURRENT:    u8 = 1;
pub const ELFOSABI_SYSV: u8 = 0;

pub const ET_CORE: u16 = 4;

pub const EM_X86_64:  u16 = 62;
pub const EM_AARCH64: u16 = 183;

pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const SHT_NULL:  u32 = 0;
pub const SHN_UNDEF: u16 = 0;

/// Extended-numbering escape: `e_phnum` saturates here and the real count moves
/// to `sh_info` of the section header at index 0.
pub const PN_XNUM: u16 = 0xffff;

pub const EHDR64_BYTES: usize = 64;
pub const PHDR64_BYTES: usize = 56;
pub const SHDR64_BYTES: usize = 64;

pub const NT_PRSTATUS:    u32 = 1;
pub const NT_PRFPREG:     u32 = 2;
pub const NT_PRPSINFO:    u32 = 3;
pub const NT_AUXV:        u32 = 6;
pub const NT_SIGINFO:     u32 = 0x5349_4749;
pub const NT_FILE:        u32 = 0x4649_4c45;
pub const NT_X86_XSTATE:  u32 = 0x0202;

/// Owner string of every note the core format defines for a process.
pub const NOTE_NAME_CORE: &[u8] = b"CORE";
/// Owner string of the arch-extended state notes.
pub const NOTE_NAME_LINUX: &[u8] = b"LINUX";

/// Note headers, names and descriptors each round up to this.
pub const NOTE_ALIGN: usize = 4;

/// `Elf64_Nhdr`: `n_namesz`, `n_descsz`, `n_type`.
pub const NOTE_HDR_BYTES: usize = 12;

/// The signal descriptor a `NT_SIGINFO` note carries.
pub const SIGINFO_NOTE_BYTES: usize = 128;

/// Program-header alignment of a `PT_NOTE` segment.
pub const NOTE_PHDR_ALIGN: u64 = 4;
