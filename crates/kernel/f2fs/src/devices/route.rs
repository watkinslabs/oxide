//! One medium over several, addressed by the volume's global block numbers.
//!
//! The volume above this reads and writes block addresses and knows nothing
//! about members; the members below know nothing about the volume's address
//! space. This is the only place the two meet, and the only place a request
//! that crosses a member boundary is split.
//!
//! Splitting is not theoretical: the boundary falls wherever a member's
//! segment count puts it, and a multi-block read that straddles it would
//! otherwise run off the end of one member and be refused, or — worse, on a
//! member large enough to accept it — read blocks belonging to nothing.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::BLKSIZE;

use super::table::DevTable;

/// One member-bounded piece of a request: which member, the block address on
/// it, where the piece starts in the caller's buffer, and how long it is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Run {
    pub member: usize,
    pub local: u64,
    pub at: usize,
    pub len: usize,
}

/// The volume's members, and the map that says which is which.
pub struct DeviceSet<S: SectorSource> {
    members: Vec<S>,
    table: DevTable,
}

impl<S: SectorSource> DeviceSet<S> {
    /// Members in the superblock's order, with the table that spans them.
    ///
    /// `Einval` when the two disagree in length: a set with fewer media than
    /// spans would route a whole member's blocks nowhere.
    /// # C: O(1)
    pub fn new(members: Vec<S>, table: DevTable) -> Result<Self, Errno> {
        if members.is_empty() || members.len() != table.len() { return Err(Errno::Einval); }
        Ok(Self { members, table })
    }

    /// # C: O(1)
    pub fn table(&self) -> &DevTable { &self.table }

    /// # C: O(1)
    pub fn members(&self) -> &[S] { &self.members }

    /// Split a request of `len` bytes at block `sector` into member-bounded
    /// runs. # C: O(runs)
    pub fn split(&self, sector: u64, len: usize) -> Result<Vec<Run>, Errno> {
        split_at(&self.table, sector, len)
    }
}

/// The split, as a function of the table alone — so the boundary arithmetic
/// is checkable without a medium behind it. # C: O(runs)
pub fn split_at(table: &DevTable, sector: u64, len: usize) -> Result<Vec<Run>, Errno> {
    let blk = BLKSIZE as u64;
    let mut out = Vec::new();
    let mut done = 0usize;
    let mut cur = sector;
    while done < len {
        let addr = u32::try_from(cur).map_err(|_| Errno::Eio)?;
        let (member, local) = table.target(addr);
        let left = (len - done) as u64;
        // A single-member set has no boundary to stop at; on a multi-member
        // one a member's last block is where the next member begins.
        let room = if table.is_multi() {
            let d = table.get(member).ok_or(Errno::Eio)?;
            if addr > d.end_blk { left } else { (u64::from(d.end_blk - addr) + 1) * blk }
        } else {
            left
        };
        let take = usize::try_from(left.min(room.max(1))).map_err(|_| Errno::Eio)?;
        out.push(Run { member, local: u64::from(local), at: done, len: take });
        done += take;
        cur += (take as u64).div_ceil(blk);
    }
    Ok(out)
}

impl<S: SectorSource> SectorSource for DeviceSet<S> {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        for r in self.split(sector, buf.len())? {
            let m = self.members.get(r.member).ok_or(Errno::Eio)?;
            m.read_sectors(r.local, &mut buf[r.at..r.at + r.len])?;
        }
        Ok(())
    }

    fn write_sectors(&self, sector: u64, buf: &[u8]) -> Result<(), Errno> {
        for r in self.split(sector, buf.len())? {
            let m = self.members.get(r.member).ok_or(Errno::Eio)?;
            m.write_sectors(r.local, &buf[r.at..r.at + r.len])?;
        }
        Ok(())
    }

    fn writable(&self) -> bool { self.members.iter().all(|m| m.writable()) }

    fn flush(&self) -> Result<(), Errno> {
        for m in &self.members { m.flush()?; }
        Ok(())
    }

    /// Every member but the first. The commit record lands on the first, so
    /// its ordering belongs to the commit; the others must be durable BEFORE
    /// that record, or it names blocks a power loss never finished writing.
    fn flush_devices(&self) -> Result<(), Errno> {
        for m in self.members.iter().skip(1) { m.flush()?; }
        Ok(())
    }
}
