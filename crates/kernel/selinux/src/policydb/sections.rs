// Non-symbol policy sections: object contexts, per-filesystem path contexts,
// and the three transition tables.

use alloc::string::String;
use alloc::vec::Vec;

use crate::context::ValidContext;
use crate::ebitmap::Ebitmap;
use crate::mls::Range;

/// Filesystem labelling behaviour declared by an `fs_use` statement.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FsUse {
    /// Per-inode label read from the `security.selinux` extended attribute.
    Xattr = 1,
    /// Per-inode label computed as a transition from the creating task.
    Trans = 2,
    /// Per-inode label taken from the creating task.
    Task = 3,
    /// Label taken from `genfscon` path prefixes.
    Genfs = 4,
    /// Filesystem carries no labels.
    None = 5,
    /// One label for the whole mount, fixed at mount time.
    Mntpoint = 6,
    /// Filesystem supplies labels natively.
    Native = 7,
}

impl FsUse {
    /// Decode a wire value; `Mntpoint` is never stored in a policy image. # C: O(1)
    pub const fn from_wire(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Xattr),
            2 => Some(Self::Trans),
            3 => Some(Self::Task),
            4 => Some(Self::Genfs),
            5 => Some(Self::None),
            7 => Some(Self::Native),
            _ => None,
        }
    }

    /// Whether this behaviour reads a per-inode extended attribute. # C: O(1)
    pub const fn uses_xattr(self) -> bool { matches!(self, Self::Xattr | Self::Native) }
}

/// Context of one initial SID.
#[derive(Clone, Debug)]
pub struct IsidCon {
    /// Initial SID number.
    pub sid: u32,
    /// Context the policy assigns it.
    pub context: ValidContext,
}

/// Context of a network port range.
#[derive(Clone, Debug)]
pub struct PortCon {
    /// IP protocol number.
    pub protocol: u8,
    /// First port of the range.
    pub low: u16,
    /// Last port of the range.
    pub high: u16,
    /// Context of ports in the range.
    pub context: ValidContext,
}

/// Context of a named network interface.
#[derive(Clone, Debug)]
pub struct NetifCon {
    /// Interface name.
    pub name: String,
    /// Context of the interface itself.
    pub context: ValidContext,
    /// Context of packets crossing it.
    pub packet_context: ValidContext,
}

/// Context of an IPv4 network node.
#[derive(Clone, Debug)]
pub struct NodeCon {
    /// Address, in network byte order as stored.
    pub addr: u32,
    /// Netmask, in network byte order as stored.
    pub mask: u32,
    /// Context of matching nodes.
    pub context: ValidContext,
}

/// Context of an IPv6 network node.
#[derive(Clone, Debug)]
pub struct Node6Con {
    /// Address words, in network byte order as stored.
    pub addr: [u32; 4],
    /// Netmask words, in network byte order as stored.
    pub mask: [u32; 4],
    /// Context of matching nodes.
    pub context: ValidContext,
}

/// Labelling behaviour and default context of one filesystem type.
#[derive(Clone, Debug)]
pub struct FsUseCon {
    /// Declared labelling behaviour.
    pub behavior: FsUse,
    /// Filesystem type name.
    pub name: String,
    /// Default context for the mount.
    pub context: ValidContext,
}

/// Context of an InfiniBand partition-key range.
#[derive(Clone, Debug)]
pub struct IbPkeyCon {
    /// Subnet prefix, as stored.
    pub subnet_prefix: u64,
    /// First partition key of the range.
    pub low: u16,
    /// Last partition key of the range.
    pub high: u16,
    /// Context of matching keys.
    pub context: ValidContext,
}

/// Context of an InfiniBand end port.
#[derive(Clone, Debug)]
pub struct IbEndportCon {
    /// Device name.
    pub name: String,
    /// Port number.
    pub port: u8,
    /// Context of the port.
    pub context: ValidContext,
}

/// Every object-context category a policy declares.
#[derive(Clone, Debug, Default)]
pub struct Ocontexts {
    /// Initial-SID contexts.
    pub isids: Vec<IsidCon>,
    /// Port contexts.
    pub ports: Vec<PortCon>,
    /// Network-interface contexts.
    pub netifs: Vec<NetifCon>,
    /// IPv4 node contexts.
    pub nodes: Vec<NodeCon>,
    /// IPv6 node contexts.
    pub nodes6: Vec<Node6Con>,
    /// Per-filesystem-type labelling behaviour.
    pub fs_use: Vec<FsUseCon>,
    /// InfiniBand partition-key contexts.
    pub ibpkeys: Vec<IbPkeyCon>,
    /// InfiniBand end-port contexts.
    pub ibendports: Vec<IbEndportCon>,
}

impl Ocontexts {
    /// Context of one initial SID. # C: O(initial SIDs)
    pub fn isid(&self, sid: u32) -> Option<&ValidContext> {
        self.isids.iter().find(|i| i.sid == sid).map(|i| &i.context)
    }

    /// Labelling behaviour declared for a filesystem type. # C: O(entries)
    pub fn fs_use_of(&self, name: &str) -> Option<&FsUseCon> {
        self.fs_use.iter().find(|f| f.name == name)
    }

    /// Context of a port, preferring an exact protocol match. # C: O(entries)
    pub fn port(&self, protocol: u8, port: u16) -> Option<&ValidContext> {
        self.ports.iter()
            .find(|p| p.protocol == protocol && (p.low..=p.high).contains(&port))
            .map(|p| &p.context)
    }
}

/// One path-prefix context within a filesystem type.
#[derive(Clone, Debug)]
pub struct GenfsPath {
    /// Path prefix, matched against the object's path within the mount.
    pub path: String,
    /// Class the entry applies to, or zero for every class.
    pub sclass: u32,
    /// Context assigned to matching objects.
    pub context: ValidContext,
}

/// Path-prefix contexts for one filesystem type.
#[derive(Clone, Debug)]
pub struct Genfs {
    /// Filesystem type name.
    pub fstype: String,
    /// Path prefixes, longest first so the first match is the most specific.
    pub paths: Vec<GenfsPath>,
}

impl Genfs {
    /// Most specific matching context for a path and class. # C: O(paths)
    ///
    /// Entries are ordered longest-prefix-first at load, so the FIRST match is
    /// the answer. Scanning in any other order silently returns a broader
    /// entry's context and mislabels every object under a nested prefix.
    pub fn lookup(&self, path: &str, sclass: u32) -> Option<&ValidContext> {
        self.paths.iter()
            .find(|p| (p.sclass == 0 || p.sclass == sclass) && path.starts_with(&p.path))
            .map(|p| &p.context)
    }
}

/// One role transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleTrans {
    /// Source role.
    pub role: u32,
    /// Target type.
    pub ty: u32,
    /// Class the transition applies to.
    pub tclass: u32,
    /// Role the transition produces.
    pub new_role: u32,
}

/// One MLS range transition.
#[derive(Clone, Debug)]
pub struct RangeTrans {
    /// Source type.
    pub source_type: u32,
    /// Target type.
    pub target_type: u32,
    /// Class the transition applies to.
    pub target_class: u32,
    /// Range the transition produces.
    pub range: Range,
}

/// One outcome of a filename transition: the source types it applies to and
/// the type it produces.
#[derive(Clone, Debug)]
pub struct FilenameTransDatum {
    /// Source types this outcome applies to.
    pub stypes: Ebitmap,
    /// Type produced for a matching source.
    pub otype: u32,
}

/// One filename-transition key and its outcomes.
#[derive(Clone, Debug)]
pub struct FilenameTrans {
    /// Target (parent directory) type.
    pub ttype: u32,
    /// Class of the object being created.
    pub tclass: u32,
    /// Exact name the transition matches.
    pub name: String,
    /// Outcomes, tried in order.
    pub data: Vec<FilenameTransDatum>,
}

impl FilenameTrans {
    /// Type produced for one source type, if any outcome names it. # C: O(outcomes)
    pub fn otype_for(&self, stype: u32) -> Option<u32> {
        self.data.iter()
            .find(|d| stype.checked_sub(1).is_some_and(|b| d.stypes.get(b)))
            .map(|d| d.otype)
    }
}
