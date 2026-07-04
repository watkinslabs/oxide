use super::*;

impl BlkState {
    pub fn serial(&self) -> &[u8; blk::BLK_SERIAL_LEN] { &self.serial }

    pub(super) fn remove(&self) {
        self.poisoned.store(true, core::sync::atomic::Ordering::Release);
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
        if !self.wait_idle_for_remove() {
            if self.cfg_va != 0 {
                unsafe { core::ptr::write_volatile((self.cfg_va + 0x14) as *mut u8, 0u8); }
            }
            return;
        }
        if self.cfg_va != 0 {
            unsafe { core::ptr::write_volatile((self.cfg_va + 0x14) as *mut u8, 0u8); }
        }
        if self.bounce_pa != 0 {
            unsafe { pmm::setup::free_contig(self.bounce_pa, pmm::Order(BOUNCE_ORDER)); }
        }
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
    }

    pub(super) fn shutdown(&self) {
        self.poisoned.store(true, core::sync::atomic::Ordering::Release);
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
        let idle = self.wait_idle_for_remove();
        if self.cfg_va != 0 {
            unsafe { core::ptr::write_volatile((self.cfg_va + 0x14) as *mut u8, 0u8); }
        }
        if !idle {
            klog::write_raw(b"[BLK-SHUTDOWN] reset with busy request quarantined\n");
        }
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
    }

    fn wait_idle_for_remove(&self) -> bool {
        #[cfg(target_os = "oxide-kernel")]
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        let mut spun: u64 = 0;
        loop {
            if !self.inflight.lock().busy {
                return true;
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if now_ns() >= deadline {
                    return false;
                }
                if spun < IO_SPIN_BUDGET {
                    spun += 1;
                    core::hint::spin_loop();
                } else {
                    park_blk();
                }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                spun += 1;
                if spun > IO_FALLBACK_SPINS {
                    return false;
                }
                core::hint::spin_loop();
            }
        }
    }

    fn submit(&self, type_: u32, sector: u64, data: &mut [u8]) -> KResult<()> {
        let h = hhdm();
        if h == 0 || !self.requestq.is_runtime_valid() || self.bounce_pa == 0 {
            return Err(BlockError::Eio);
        }
        let is_flush = type_ == blk::VIRTIO_BLK_T_FLUSH;
        let is_in = type_ == blk::VIRTIO_BLK_T_IN
            || type_ == blk::VIRTIO_BLK_T_GET_ID;
        let data_len: u32 = if is_flush { 0 } else { data.len() as u32 };
        if data_len as usize > blk::BOUNCE_DATA_BYTES {
            return Err(BlockError::Einval);
        }
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            return Err(BlockError::Eio);
        }
        self.acquire_turn();
        if self.poisoned.load(core::sync::atomic::Ordering::Acquire) {
            self.release_turn();
            return Err(BlockError::Eio);
        }
        let r = self.do_request(h, type_, sector, data, is_in, is_flush, data_len);
        if matches!(r, Err(BlockError::Eio))
            && self.poisoned.load(core::sync::atomic::Ordering::Acquire)
        {
            #[cfg(target_os = "oxide-kernel")]
            BLK_COMPL.wake_all();
            return r;
        }
        self.release_turn();
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn do_request(&self, h: u64, type_: u32, sector: u64, data: &mut [u8],
                  is_in: bool, is_flush: bool, data_len: u32) -> KResult<()> {
        let bounce = h.wrapping_add(self.bounce_pa) as *mut u8;
        let mut hdr = [0u8; 16];
        blk::encode_header(&mut hdr, type_, sector);
        unsafe {
            for (i, b) in hdr.iter().enumerate() {
                core::ptr::write_volatile(bounce.add(HDR_OFF + i), *b);
            }
            if !is_in && !is_flush {
                for (i, b) in data.iter().enumerate() {
                    core::ptr::write_volatile(bounce.add(DATA_OFF + i), *b);
                }
            }
            core::ptr::write_volatile(bounce.add(STATUS_OFF), 0xFFu8);
        }

        let hdr_pa = self.bounce_pa + HDR_OFF as u64;
        let data_pa = self.bounce_pa + DATA_OFF as u64;
        let status_pa = self.bounce_pa + STATUS_OFF as u64;
        let (descs, n) = blk::build_chain(is_in, hdr_pa, data_pa, data_len, status_pa);

        let desc_tbl = h.wrapping_add(self.requestq.desc_pa) as *mut u64;
        unsafe {
            for (i, d) in descs.iter().take(n).enumerate() {
                let (w0, w1) = blk::pack_desc(d);
                core::ptr::write_volatile(desc_tbl.add(i * 2), w0);
                core::ptr::write_volatile(desc_tbl.add(i * 2 + 1), w1);
            }
        }

        let avail = h.wrapping_add(self.requestq.driver_pa) as *mut u16;
        let qsz = self.requestq.size;
        let target = {
            let mut g = self.inflight.lock();
            let slot = g.avail_idx % qsz;
            unsafe {
                core::ptr::write_volatile(avail.add(2 + slot as usize), 0u16);
                core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                g.avail_idx = g.avail_idx.wrapping_add(1);
                core::ptr::write_volatile(avail.add(1), g.avail_idx);
            }
            g.avail_idx
        };
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        if self.requestq.notify_va != 0 {
            unsafe {
                core::ptr::write_volatile(
                    self.requestq.notify_va as *mut u16,
                    self.requestq.index,
                );
            }
        }

        self.wait_for_completion(h, target)?;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        let status = unsafe { core::ptr::read_volatile(bounce.add(STATUS_OFF)) };
        blk::decode_status(status).map_err(|_| BlockError::Eio)?;
        if is_in {
            unsafe {
                for (i, b) in data.iter_mut().enumerate() {
                    *b = core::ptr::read_volatile(bounce.add(DATA_OFF + i));
                }
            }
        }
        Ok(())
    }

    fn wait_for_completion(&self, h: u64, target: u16) -> KResult<()> {
        let used = h.wrapping_add(self.requestq.device_pa) as *const u16;
        #[cfg(target_os = "oxide-kernel")]
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        let mut spun: u64 = 0;
        loop {
            let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
            if uidx == target {
                self.inflight.lock().used_seen = uidx;
                return Ok(());
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if now_ns() >= deadline {
                    self.poisoned.store(true, core::sync::atomic::Ordering::Release);
                    klog::write_raw(b"[BLK-TIMEOUT] device poisoned, used stuck\n");
                    return Err(BlockError::Eio);
                }
                if spun < IO_SPIN_BUDGET { spun += 1; core::hint::spin_loop(); }
                else { park_blk(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                spun += 1;
                if spun > IO_FALLBACK_SPINS { return Err(BlockError::Eio); }
                core::hint::spin_loop();
            }
        }
    }

    fn acquire_turn(&self) {
        #[cfg(target_os = "oxide-kernel")]
        let mut spun: u64 = 0;
        loop {
            if self.poisoned.load(core::sync::atomic::Ordering::Acquire) { return; }
            {
                let mut g = self.inflight.lock();
                if !g.busy { g.busy = true; return; }
            }
            #[cfg(target_os = "oxide-kernel")]
            { if spun < IO_SPIN_BUDGET { spun += 1; core::hint::spin_loop(); } else { park_blk(); } }
            #[cfg(not(target_os = "oxide-kernel"))]
            { core::hint::spin_loop(); }
        }
    }

    fn release_turn(&self) {
        self.inflight.lock().busy = false;
        #[cfg(target_os = "oxide-kernel")]
        BLK_COMPL.wake_all();
    }

    pub(super) fn get_id(&self) -> KResult<[u8; blk::BLK_SERIAL_LEN]> {
        let mut id = [0u8; blk::BLK_SERIAL_LEN];
        self.submit(blk::VIRTIO_BLK_T_GET_ID, 0, &mut id)?;
        Ok(id)
    }
}

impl BlockDevice for BlkState {
    fn block_size(&self) -> u32 { self.blk_size }

    fn capacity_blocks(&self) -> u64 {
        blk::capacity_blocks(self.capacity, self.blk_size)
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let sec = blk::VIRTIO_BLK_SECTOR_BYTES as usize;
        match req.op {
            BlockOp::Flush => self.submit(blk::VIRTIO_BLK_T_FLUSH, 0, &mut []),
            BlockOp::Read | BlockOp::Write => {
                let bs = self.blk_size as usize;
                let nbytes = (req.len_blocks as usize)
                    .checked_mul(bs).ok_or(BlockError::Einval)?;
                if req.op == BlockOp::Read {
                    if req.buffer.len() < nbytes { req.buffer.resize(nbytes, 0); }
                } else if req.buffer.len() < nbytes {
                    return Err(BlockError::Einval);
                }
                let (base_sector, total_sectors) =
                    blk::sector_plan(req.start_block, req.len_blocks, self.blk_size)
                        .ok_or(BlockError::Einval)?;
                let type_ = if req.op == BlockOp::Read {
                    blk::VIRTIO_BLK_T_IN
                } else {
                    blk::VIRTIO_BLK_T_OUT
                };
                let mut tmp: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                let mut chunk_idx = 0u64;
                while let Some((chunk_base, chunk_sectors, off)) = blk::chunk_plan(
                    base_sector, total_sectors, chunk_idx, blk::BOUNCE_DATA_SECTORS,
                ) {
                    let clen = chunk_sectors as usize * sec;
                    tmp.resize(clen, 0);
                    if req.op == BlockOp::Write {
                        tmp.copy_from_slice(&req.buffer[off..off + clen]);
                    }
                    self.submit(type_, chunk_base, &mut tmp[..clen])?;
                    if req.op == BlockOp::Read {
                        req.buffer[off..off + clen].copy_from_slice(&tmp[..clen]);
                    }
                    chunk_idx += 1;
                }
                Ok(())
            }
            BlockOp::Discard => Err(BlockError::Eopnotsupp),
        }
    }

    fn flush(&self) -> KResult<()> {
        self.submit(blk::VIRTIO_BLK_T_FLUSH, 0, &mut [])
    }
}
