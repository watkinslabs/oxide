//! Typed registry records; mutable fields remain crate-owned.
use super::*;
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Root { LocalMachine, CurrentUser, Classes }

pub const HKEY_LOCAL_MACHINE: u64 = 0x8000_0000;
pub const HKEY_CURRENT_USER: u64 = 0x8000_0001;
pub const HKEY_CLASSES_ROOT: u64 = 0x8000_0002;

impl Root {
    pub(crate) fn name(self) -> &'static str {
        match self { Self::LocalMachine => "HKLM", Self::CurrentUser => "HKCU", Self::Classes => "HKCR" }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ValueType { None = 0, String = 1, ExpandString = 2, Binary = 3, Dword = 4, MultiString = 7, Qword = 11 }

impl ValueType {
    pub(crate) fn decode(raw: u32) -> Option<Self> {
        Some(match raw { 0 => Self::None, 1 => Self::String, 2 => Self::ExpandString, 3 => Self::Binary, 4 => Self::Dword, 7 => Self::MultiString, 11 => Self::Qword, _ => return None })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Value { pub kind: ValueType, pub data: Vec<u8> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyInfo { pub name: String, pub subkeys: u32, pub max_subkey: u32, pub values: u32, pub max_value_name: u32, pub max_value_data: u32 }

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyHandle(pub(crate) u64);

impl KeyHandle {
    pub const fn raw(self) -> u64 { self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Key { pub path: String, pub(crate) values: BTreeMap<String, (String, Value)> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error { InvalidPath, MissingKey, MissingValue, InvalidFile, Io(String), Deleted, AlreadyServing }

impl From<io::Error> for Error { fn from(error: io::Error) -> Self { Self::Io(error.to_string()) } }

/// Canonical userspace registry database. Key identity is case-insensitive;
/// display spelling is retained for enumeration and persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registry { pub(crate) keys: BTreeMap<String, Key>, pub(crate) handles: BTreeMap<KeyHandle, String>, pub(crate) deleted: BTreeSet<KeyHandle>, pub(crate) next_handle: u64 }

/// One runtime/user registry session backed by one Linux file.
pub struct RegistryStore { pub(crate) registry: Registry, pub(crate) path: PathBuf, pub(crate) _lock: File, pub(crate) dirty: bool, pub(crate) subscriptions: BTreeMap<u64, Subscription>, pub(crate) next_subscription: u64 }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Subscription { pub(crate) key: KeyHandle, pub(crate) filter: u64, pub(crate) subtree: bool, pub(crate) pending: bool }

#[derive(Debug)]
pub enum Request {
    Open { root: Root, subkey: String },
    Create { root: Root, subkey: String },
    OpenRelative { key: KeyHandle, subkey: String },
    CreateRelative { key: KeyHandle, subkey: String },
    Rename { key: KeyHandle, name: String },
    Set { key: KeyHandle, name: String, value: Value },
    DeleteValue { key: KeyHandle, name: String },
    DeleteKey { key: KeyHandle },
    Query { key: KeyHandle, name: String },
    EnumKeys { key: KeyHandle },
    EnumValues { key: KeyHandle },
    QueryKey { key: KeyHandle },
    Close { key: KeyHandle },
    Flush { key: KeyHandle },
    SaveHive { key: KeyHandle },
    LoadHive { root: Root, subkey: String, bytes: Vec<u8> },
    LoadHiveRelative { key: KeyHandle, subkey: String, bytes: Vec<u8> },
    QueryPath { key: KeyHandle },
    Subscribe { key: KeyHandle, filter: u64, subtree: bool },
    PollSubscription { subscription: u64 },
    Unsubscribe { subscription: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Response { Handle(KeyHandle), Value(Value), Keys(Vec<String>), Values(Vec<(String, Value)>), KeyInfo(KeyInfo), Bytes(Vec<u8>), Text(String), Subscription(u64), Notification, Success, Failure(Error) }
