// Numbers and names that cross a boundary: the filesystem magic userspace
// reads back from `statfs`, the record-type names that spell the FILENAME a
// crash-report collector globs for, and the crash reasons a dumper filters on.

/// `PSTOREFS_MAGIC` — the `statfs(2)` `f_type` of a pstore mount.
pub const PSTOREFS_MAGIC: u64 = 0x6165_676C;

/// Record classes, in the reference's order — the order fixes the numeric
/// value a backend stores and reads back, so an existing zone written by a
/// previous boot decodes to the same class.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum RecordType {
    Dmesg = 0,
    Mce = 1,
    Console = 2,
    Ftrace = 3,
    Rtas = 4,
    PowerpcOfw = 5,
    PowerpcCommon = 6,
    Pmsg = 7,
    PowerpcOpal = 8,
}

/// The names, in `RecordType` order. A record file is
/// `<type>-<backend>-<id>`, so these strings are ABI for every tool that
/// looks for `dmesg-ramoops-0`.
const TYPE_NAMES: [&str; 9] = [
    "dmesg", "mce", "console", "ftrace", "rtas",
    "powerpc-ofw", "powerpc-common", "pmsg", "powerpc-opal",
];

impl RecordType {
    /// `pstore_type_to_name`. # C: O(1)
    pub fn name(self) -> &'static str { TYPE_NAMES[self as usize] }

    /// `pstore_name_to_type`. `None` is the reference's `PSTORE_TYPE_MAX`
    /// sentinel — no class carries that name. # C: O(N_types)
    pub fn from_name(name: &str) -> Option<RecordType> {
        let mut i = 0;
        while i < TYPE_NAMES.len() {
            if TYPE_NAMES[i] == name { return Self::from_raw(i as u8); }
            i += 1;
        }
        None
    }

    /// Decode a stored discriminant. # C: O(1)
    pub fn from_raw(v: u8) -> Option<RecordType> {
        match v {
            0 => Some(RecordType::Dmesg),
            1 => Some(RecordType::Mce),
            2 => Some(RecordType::Console),
            3 => Some(RecordType::Ftrace),
            4 => Some(RecordType::Rtas),
            5 => Some(RecordType::PowerpcOfw),
            6 => Some(RecordType::PowerpcCommon),
            7 => Some(RecordType::Pmsg),
            8 => Some(RecordType::PowerpcOpal),
            _ => None,
        }
    }
}

/// Why the kernel is dumping its log, in the reference's priority order:
/// anything numerically above [`DumpReason::Oops`] is NOT recorded by a
/// default-configured backend.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DumpReason {
    Undef = 0,
    Panic = 1,
    Oops = 2,
    Emerg = 3,
    Shutdown = 4,
}

impl DumpReason {
    /// The word that leads a dmesg record's header line, so a reader can tell
    /// a panic dump from a shutdown one. # C: O(1)
    pub fn as_str(self) -> &'static str {
        match self {
            DumpReason::Undef => "Unknown",
            DumpReason::Panic => "Panic",
            DumpReason::Oops => "Oops",
            DumpReason::Emerg => "Emergency",
            DumpReason::Shutdown => "Shutdown",
        }
    }

    /// Decode the raw reason the log layer passes across the hook boundary.
    /// # C: O(1)
    pub fn from_raw(v: u8) -> DumpReason {
        match v {
            1 => DumpReason::Panic,
            2 => DumpReason::Oops,
            3 => DumpReason::Emerg,
            4 => DumpReason::Shutdown,
            _ => DumpReason::Undef,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names_round_trip() {
        for raw in 0u8..9 {
            let t = RecordType::from_raw(raw).unwrap();
            assert_eq!(RecordType::from_name(t.name()), Some(t));
        }
        assert_eq!(RecordType::from_raw(9), None);
        assert_eq!(RecordType::from_name("nosuchtype"), None);
    }

    #[test]
    fn dmesg_and_console_names_are_the_filename_prefixes() {
        assert_eq!(RecordType::Dmesg.name(), "dmesg");
        assert_eq!(RecordType::Console.name(), "console");
    }

    #[test]
    fn reasons_order_by_priority() {
        assert!(DumpReason::Panic < DumpReason::Oops);
        assert!(DumpReason::Oops < DumpReason::Emerg);
        assert!(DumpReason::Emerg < DumpReason::Shutdown);
        assert_eq!(DumpReason::from_raw(4), DumpReason::Shutdown);
        assert_eq!(DumpReason::from_raw(77), DumpReason::Undef);
    }
}
