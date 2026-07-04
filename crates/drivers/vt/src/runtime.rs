use super::*;

pub unsafe fn init() -> KResult<()> {
    let mut g = SLOTS.lock();
    g[0].allocated = true;
    ACTIVE_VT.store(1, Ordering::Release);
    Ok(())
}

pub fn active() -> u8 { ACTIVE_VT.load(Ordering::Acquire) }

pub fn scrolldelta(lines: isize) {
    #[cfg(target_os = "oxide-kernel")]
    fbcon::kernel::scrolldelta(lines);
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = lines;
}

pub fn unblank() {
    tiocl::set_blanked(false);
    #[cfg(target_os = "oxide-kernel")]
    fbcon::kernel::force_repaint();
}

pub fn blank() { tiocl::set_blanked(true); }

pub fn openqry() -> KResult<u8> {
    let g = SLOTS.lock();
    for (i, slot) in g.iter().enumerate() {
        if !slot.allocated { return Ok((i + 1) as u8); }
    }
    Err(Error::Busy)
}

pub fn activate(n: u8) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    let g = SLOTS.lock();
    let cur = ACTIVE_VT.load(Ordering::Acquire);
    if cur > 0 && g[(cur - 1) as usize].locked { return Err(Error::Busy); }
    if cur > 0 && n != cur {
        let s = &g[(cur - 1) as usize];
        if s.vt_mode.mode == VT_PROCESS && owner_alive(s.owner_vpid, s.owner_tid) {
            let (pid, sig) = (s.owner_vpid, s.vt_mode.relsig);
            drop(g);
            PENDING_SWITCH.store(n, Ordering::Release);
            fire_signal(pid, sig);
            return Ok(());
        }
    }
    drop(g);
    do_switch(n);
    Ok(())
}

fn do_switch(n: u8) {
    let (acq_pid, acq_sig) = {
        let mut g = SLOTS.lock();
        g[(n - 1) as usize].allocated = true;
        let s = &g[(n - 1) as usize];
        if s.vt_mode.mode == VT_PROCESS && owner_alive(s.owner_vpid, s.owner_tid) {
            (s.owner_vpid, s.vt_mode.acqsig)
        } else {
            (0, 0)
        }
    };
    ACTIVE_VT.store(n, Ordering::Release);
    #[cfg(target_os = "oxide-kernel")]
    {
        fbcon::kernel::switch_vt(n);
        tty::live::set_foreground(n);
    }
    fire_signal(acq_pid, acq_sig);
    fire_switch(n);
}

pub fn reldisp(ack: i32, caller_vpid: u32, caller_tid: u32) -> KResult<()> {
    let pending = PENDING_SWITCH.load(Ordering::Acquire);
    if pending == 0 { return Ok(()); }
    let cur = ACTIVE_VT.load(Ordering::Acquire);
    {
        let g = SLOTS.lock();
        if cur < 1 || cur as usize > MAX_NR_CONSOLES { return Err(Error::Perm); }
        let s = &g[(cur - 1) as usize];
        let is_owner = s.vt_mode.mode == VT_PROCESS
            && s.owner_vpid == caller_vpid
            && s.owner_tid == caller_tid
            && !(caller_vpid == 0 && caller_tid == 0);
        if !is_owner { return Err(Error::Perm); }
    }
    PENDING_SWITCH.store(0, Ordering::Release);
    if ack == 0 { return Ok(()); }
    do_switch(pending);
    Ok(())
}

pub fn get_state() -> VtStat {
    let g = SLOTS.lock();
    let mut bits = 0u16;
    for (i, slot) in g.iter().enumerate() {
        if slot.allocated { bits |= 1 << (i + 1); }
    }
    VtStat {
        v_active: ACTIVE_VT.load(Ordering::Acquire) as u16,
        v_signal: 0,
        v_state: bits,
    }
}

pub fn disallocate(n: u8) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    if ACTIVE_VT.load(Ordering::Acquire) == n { return Err(Error::Busy); }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize] = VtSlot::default();
    Ok(())
}

pub fn set_kd_mode(n: u8, mode: u32) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    if mode != KD_TEXT && mode != KD_GRAPHICS && mode != KD_TEXT0 && mode != KD_TEXT1 {
        return Err(Error::Inval);
    }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].kd_mode = mode;
    Ok(())
}

pub fn set_kb_mode(n: u8, mode: u32) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    if mode > K_OFF { return Err(Error::Inval); }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].kb_mode = mode;
    Ok(())
}

pub fn lock_switch(n: u8, locked: bool) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].locked = locked;
    Ok(())
}

pub fn set_vt_mode(n: u8, mode: VtMode, vpid: u32, tid: u32) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    if mode.mode != VT_AUTO && mode.mode != VT_PROCESS && mode.mode != VT_ACKACQ {
        return Err(Error::Inval);
    }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].vt_mode = mode;
    if mode.mode == VT_PROCESS {
        g[(n - 1) as usize].owner_vpid = vpid;
        g[(n - 1) as usize].owner_tid = tid;
    } else {
        g[(n - 1) as usize].owner_vpid = 0;
        g[(n - 1) as usize].owner_tid = 0;
    }
    Ok(())
}

pub fn set_leds(n: u8, leds: u32) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].leds = leds;
    Ok(())
}

pub fn resize(n: u8, rows: u16, cols: u16) -> KResult<()> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return Err(Error::Inval); }
    if rows == 0 || cols == 0 { return Err(Error::Inval); }
    #[cfg(target_os = "oxide-kernel")]
    {
        if !fbcon::kernel::resize_vt(n, cols, rows) { return Err(Error::Inval); }
    }
    let mut g = SLOTS.lock();
    g[(n - 1) as usize].cols = cols;
    g[(n - 1) as usize].rows = rows;
    Ok(())
}

pub fn slot(n: u8) -> Option<VtSlotSnap> {
    if n < 1 || n as usize > MAX_NR_CONSOLES { return None; }
    let g = SLOTS.lock();
    let s = &g[(n - 1) as usize];
    Some(VtSlotSnap {
        kd_mode: s.kd_mode,
        kb_mode: s.kb_mode,
        vt_mode: s.vt_mode,
        owner_vpid: s.owner_vpid,
        owner_tid: s.owner_tid,
        leds: s.leds,
        cols: s.cols,
        rows: s.rows,
        locked: s.locked,
        allocated: s.allocated,
    })
}
