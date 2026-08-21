//! Sole physical collision-list construction for terminal restore.

use alloc::vec::Vec;

use super::{Collision, Error, KResult, Memory, SafeRestore};
use crate::hibernate::format::{Page, PAGE_SIZE};

pub const COLLISION_HEADER_BYTES: usize = 16;
pub const COLLISIONS_PER_PAGE: usize = (PAGE_SIZE - COLLISION_HEADER_BYTES)
    / core::mem::size_of::<Collision>();

fn put_u64(page: &mut Page, offset: usize, value: u64) {
    page[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

impl<F> SafeRestore<F> {
    /// Serialize the generic collision truth into pinned physical list pages.
    /// # C: O(collision pages)
    pub fn prepare_collision_chain<M: Memory<Frame = F>>(&mut self, memory: &mut M) -> KResult<()> {
        if self.collision_prepared { return Err(Error::Busy); }
        self.collision_prepared = true;
        let collisions = self.collision_count();
        if collisions == 0 { return Ok(()); }
        let nodes = collisions.div_ceil(COLLISIONS_PER_PAGE);
        let mut indices = Vec::new();
        indices.try_reserve_exact(nodes).map_err(|_| Error::Nomem)?;
        for _ in 0..nodes { indices.push(self.allocate_control(memory)?); }
        self.collision_head_pa = self.control_pfn(indices[0]).ok_or(Error::Nodata)?
            .checked_mul(PAGE_SIZE as u64).ok_or(Error::Inval)?;

        let mut page = [0u8; PAGE_SIZE];
        let mut node = 0usize;
        let mut count = 0usize;
        for collision_index in 0..collisions {
            let collision = self.image.collisions[collision_index];
            let offset = COLLISION_HEADER_BYTES + count * core::mem::size_of::<Collision>();
            put_u64(&mut page, offset, collision.source_pfn.checked_mul(PAGE_SIZE as u64)
                .ok_or(Error::Inval)?);
            put_u64(&mut page, offset + 8, collision.destination_pfn.checked_mul(PAGE_SIZE as u64)
                .ok_or(Error::Inval)?);
            count += 1;
            if count == COLLISIONS_PER_PAGE || node + 1 == nodes && count + node * COLLISIONS_PER_PAGE == collisions {
                let next = if node + 1 < nodes {
                    self.control_pfn(indices[node + 1]).ok_or(Error::Nodata)?
                        .checked_mul(PAGE_SIZE as u64).ok_or(Error::Inval)?
                } else { 0 };
                put_u64(&mut page, 0, next);
                put_u64(&mut page, 8, count as u64);
                let frame = self.control_mut(indices[node]).ok_or(Error::Nodata)?;
                memory.write(frame, &page);
                page.fill(0);
                node += 1;
                count = 0;
            }
        }
        if node != nodes || count != 0 { return Err(Error::Inval); }
        self.collision_nodes = indices;
        Ok(())
    }

    /// Physical head of the owned collision chain, or zero for no collisions. # C: O(1)
    pub const fn collision_head_pa(&self) -> u64 { self.collision_head_pa }

    /// Number of pinned collision-list pages. # C: O(1)
    pub fn collision_node_count(&self) -> usize { self.collision_nodes.len() }
}
