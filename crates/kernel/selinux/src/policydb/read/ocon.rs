// Object contexts and per-filesystem path contexts.
//
// The categories are positional: the image lists exactly the number the header
// declared, in a fixed order, and each has its own record layout. A category
// whose bytes are skipped or misread desynchronises everything after it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::policydb::sections::{FsUse, FsUseCon, Genfs, GenfsPath, IbEndportCon, IbPkeyCon,
                                IsidCon, NetifCon, Node6Con, NodeCon, Ocontexts, PortCon};
use crate::policydb::symbols::{Symbols, SYM_CLASSES};
use crate::reader::Reader;

use super::ctx;

/// Initial SIDs.
const OCON_ISID: usize = 0;
/// Deprecated per-filesystem contexts, still present in the stream.
const OCON_FS: usize = 1;
/// Network ports.
const OCON_PORT: usize = 2;
/// Network interfaces.
const OCON_NETIF: usize = 3;
/// IPv4 nodes.
const OCON_NODE: usize = 4;
/// Filesystem labelling behaviour.
const OCON_FSUSE: usize = 5;
/// IPv6 nodes.
const OCON_NODE6: usize = 6;
/// InfiniBand partition keys.
const OCON_IBPKEY: usize = 7;
/// InfiniBand end ports.
const OCON_IBENDPORT: usize = 8;

/// Genfs entry applying to every class.
const GENFS_ANY_CLASS: u32 = 0;

/// Read every object-context category the header declared. # C: O(records)
pub fn read_all(r: &mut Reader<'_>, mls: bool, s: &Symbols, ocon_num: u32) -> Result<Ocontexts> {
    let mut o = Ocontexts::default();
    for category in 0..ocon_num as usize {
        let nel = r.u32()?;
        reserve(&mut o, category, nel)?;
        for _ in 0..nel { read_one(r, mls, s, category, &mut o)?; }
    }
    Ok(o)
}

fn reserve(o: &mut Ocontexts, category: usize, nel: u32) -> Result<()> {
    let n = nel as usize;
    let res = match category {
        OCON_ISID => o.isids.try_reserve(n),
        OCON_PORT => o.ports.try_reserve(n),
        OCON_NETIF => o.netifs.try_reserve(n),
        OCON_NODE => o.nodes.try_reserve(n),
        OCON_FSUSE => o.fs_use.try_reserve(n),
        OCON_NODE6 => o.nodes6.try_reserve(n),
        OCON_IBPKEY => o.ibpkeys.try_reserve(n),
        OCON_IBENDPORT => o.ibendports.try_reserve(n),
        _ => Ok(()),
    };
    res.map_err(|_| Error::NoMemory)
}

fn read_one(r: &mut Reader<'_>, mls: bool, s: &Symbols, category: usize, o: &mut Ocontexts)
    -> Result<()>
{
    match category {
        OCON_ISID => {
            let sid = r.u32()?;
            o.isids.push(IsidCon { sid, context: ctx::read(r, mls, s)? });
        }
        OCON_FS => {
            // Superseded by fs_use, but the records are still written; both
            // contexts must be consumed even though nothing consults them.
            let len = r.u32()?;
            let _name = r.string_of(len)?;
            let _context = ctx::read(r, mls, s)?;
            let _packet_context = ctx::read(r, mls, s)?;
        }
        OCON_PORT => {
            let [protocol, low, high] = r.u32_array::<3>()?;
            let protocol = u8::try_from(protocol).map_err(|_| Error::Malformed)?;
            let (low, high) = port_range(low, high)?;
            o.ports.push(PortCon { protocol, low, high, context: ctx::read(r, mls, s)? });
        }
        OCON_NETIF => {
            let len = r.u32()?;
            let name = String::from(r.string_of(len)?);
            let context = ctx::read(r, mls, s)?;
            let packet_context = ctx::read(r, mls, s)?;
            o.netifs.push(NetifCon { name, context, packet_context });
        }
        OCON_NODE => {
            // Address and mask are stored in network order and compared
            // against packet fields in the same order; byte-swapping here
            // would silently match a different subnet.
            let [addr, mask] = r.u32_array::<2>()?;
            o.nodes.push(NodeCon { addr, mask, context: ctx::read(r, mls, s)? });
        }
        OCON_FSUSE => {
            let [behavior, len] = r.u32_array::<2>()?;
            let behavior = FsUse::from_wire(behavior).ok_or(Error::Malformed)?;
            let name = String::from(r.string_of(len)?);
            o.fs_use.push(FsUseCon { behavior, name, context: ctx::read(r, mls, s)? });
        }
        OCON_NODE6 => {
            let addr = r.u32_array::<4>()?;
            let mask = r.u32_array::<4>()?;
            o.nodes6.push(Node6Con { addr, mask, context: ctx::read(r, mls, s)? });
        }
        OCON_IBPKEY => {
            let subnet_prefix = r.u64()?;
            let [low, high] = r.u32_array::<2>()?;
            let low = u16::try_from(low).map_err(|_| Error::Malformed)?;
            let high = u16::try_from(high).map_err(|_| Error::Malformed)?;
            if high < low { return Err(Error::Malformed); }
            o.ibpkeys.push(IbPkeyCon {
                subnet_prefix, low, high, context: ctx::read(r, mls, s)?,
            });
        }
        OCON_IBENDPORT => {
            let len = r.u32()?;
            let name = String::from(r.string_of(len)?);
            let port = r.u32()?;
            if port == 0 { return Err(Error::Malformed); }
            let port = u8::try_from(port).map_err(|_| Error::Malformed)?;
            o.ibendports.push(IbEndportCon { name, port, context: ctx::read(r, mls, s)? });
        }
        _ => return Err(Error::Malformed),
    }
    Ok(())
}

/// Validate a port range: nonzero, in range, and ordered. # C: O(1)
fn port_range(low: u32, high: u32) -> Result<(u16, u16)> {
    let low = u16::try_from(low).map_err(|_| Error::Malformed)?;
    let high = u16::try_from(high).map_err(|_| Error::Malformed)?;
    if low == 0 || high < low { return Err(Error::Malformed); }
    Ok((low, high))
}

/// Read the per-filesystem path-context table. # C: O(paths log paths)
pub fn read_genfs(r: &mut Reader<'_>, mls: bool, s: &Symbols) -> Result<Vec<Genfs>> {
    let nel = r.u32()?;
    let mut out: Vec<Genfs> = Vec::new();
    out.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let len = r.u32()?;
        let fstype = String::from(r.string_of(len)?);
        if out.iter().any(|g| g.fstype == fstype) { return Err(Error::Duplicate); }
        let npath = r.u32()?;
        let mut paths: Vec<GenfsPath> = Vec::new();
        paths.try_reserve(npath as usize).map_err(|_| Error::NoMemory)?;
        for _ in 0..npath {
            let len = r.u32()?;
            let path = String::from(r.string_of(len)?);
            let sclass = r.u32()?;
            if sclass != GENFS_ANY_CLASS { ctx::check_value(sclass, s.nprim[SYM_CLASSES])?; }
            if paths.iter().any(|p| p.path == path && p.sclass == sclass) {
                return Err(Error::Duplicate);
            }
            paths.push(GenfsPath { path, sclass, context: ctx::read(r, mls, s)? });
        }
        // Lookup takes the first match, so the most specific prefix must come
        // first; any other order labels a nested path with its parent's
        // context. The sort is stable, so equal-length prefixes keep the
        // policy's own order.
        paths.sort_by_key(|p| core::cmp::Reverse(p.path.len()));
        out.push(Genfs { fstype, paths });
    }
    Ok(out)
}
