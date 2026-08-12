use super::*;

pub(super) fn pcm_info_scan(device_key: DeviceKey) -> Option<(u32, u32)> {
    let mut g = CTX.lock_bh::<crate::state::SndBh>();
    let ctx = g.iter_mut().find(|ctx| ctx.device_key == device_key)?;
    let count = ctx.streams;
    if count == 0 {
        return Some((0, 0));
    }
    let h = ctx.hhdm;

    let req = h.wrapping_add(ctx.scratch_pa + REQ_OFF) as *mut u32;
    // SAFETY: HHDM view of the control scratch frame this Ctx owns; the four
    // u32 stores build a virtio_snd_query_info at REQ_OFF, and REQ_OFF plus
    // QUERY_INFO_SIZE stays below RESP_OFF, so the request never overlaps the
    // response half of the same frame. The CTX lock makes this the only writer.
    unsafe {
        core::ptr::write_volatile(req.add(0), VIRTIO_SND_R_PCM_INFO);
        core::ptr::write_volatile(req.add(1), 0);
        core::ptr::write_volatile(req.add(2), count);
        core::ptr::write_volatile(req.add(3), PCM_INFO_SIZE as u32);
    }

    let want = SND_HDR_SIZE + count as usize * PCM_INFO_SIZE;
    let resp_len = want.min(SND_FRAME_BYTES.saturating_sub(RESP_OFF as usize));
    let status = submit_ctl(ctx, QUERY_INFO_SIZE, resp_len)?;
    if status != VIRTIO_SND_S_OK {
        return None;
    }

    let entries = ((resp_len - SND_HDR_SIZE) / PCM_INFO_SIZE).min(count as usize);
    let base = h.wrapping_add(ctx.scratch_pa + RESP_OFF + SND_HDR_SIZE as u64) as *const u8;
    let (mut out, mut input) = (0u32, 0u32);
    let mut first_out: Option<u32> = None;
    let mut first_in: Option<u32> = None;
    for i in 0..entries {
        let e = base.wrapping_add(i * PCM_INFO_SIZE);
        // SAFETY: HHDM view of the response half of the scratch frame the
        // device just filled; `entries` was derived from `resp_len`, itself
        // clamped to the frame, so every `e + off` with off < PCM_INFO_SIZE
        // stays inside the bytes the device was allowed to write.
        let rd8 = |off: usize| -> u8 { unsafe { core::ptr::read_volatile(e.add(off)) } };
        let rd64 = |off: usize| -> u64 {
            let mut v = 0u64;
            for b in 0..8 {
                v |= (rd8(off + b) as u64) << (b * 8);
            }
            v
        };
        if rd8(PCM_INFO_DIR_OFF) == VIRTIO_SND_D_INPUT {
            input += 1;
            if first_in.is_none() {
                first_in = Some(i as u32);
                ctx.in_formats = rd64(8);
                ctx.in_rates = rd64(16);
                ctx.in_ch_min = rd8(25).max(1);
                ctx.in_ch_max = rd8(26).max(ctx.in_ch_min);
            }
        } else {
            out += 1;
            if first_out.is_none() {
                first_out = Some(i as u32);
                ctx.out_formats = rd64(8);
                ctx.out_rates = rd64(16);
                ctx.out_ch_min = rd8(25).max(1);
                ctx.out_ch_max = rd8(26).max(ctx.out_ch_min);
            }
        }
    }
    ctx.out_stream = first_out;
    ctx.in_stream = first_in;
    Some((out, input))
}

pub(super) fn submit_ctl(ctx: &mut Ctx, req_len: usize, resp_len: usize) -> Option<u32> {
    let controlq = ctx.controlq.as_mut()?;
    if controlq.submit(&[
        virtio::SplitQueueSeg { dma: ctx.scratch_pa + REQ_OFF, len: req_len as u32, device_writes: false },
        virtio::SplitQueueSeg { dma: ctx.scratch_pa + RESP_OFF, len: resp_len as u32, device_writes: true },
    ]).is_err() { return None; }
    let mut retired = false;
    for _ in 0..CTL_POLL_BUDGET {
        match controlq.pop_used() {
            Ok(Some(_)) => { retired = true; break; }
            Ok(None) => core::hint::spin_loop(),
            Err(_) => return None,
        }
    }
    if !retired { return None; }

    let st = ctx.hhdm.wrapping_add(ctx.scratch_pa + RESP_OFF) as *const u32;
    // SAFETY: HHDM view of the response half of the driver's own scratch
    // frame, read only after used.idx reached `target` and the acquire fence
    // above; the status code is the leading aligned u32 of every response.
    Some(unsafe { core::ptr::read_volatile(st) })
}
