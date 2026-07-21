pub fn syscall_name(nr: u32) -> Option<&'static str> {
    use syscall::nrs::*;
    Some(match nr as u64 {
        NR_READ => "read",
        NR_GETDENTS64 => "getdents64",
        NR_WRITE => "write",
        NR_POLL => "poll",
        NR_PPOLL => "ppoll",
        NR_SELECT => "select",
        NR_PSELECT6 => "pselect6",
        NR_IOCTL => "ioctl",
        NR_PAUSE => "pause",
        NR_NANOSLEEP => "nanosleep",
        NR_CLOCK_NANOSLEEP => "clk_nanosl",
        NR_RT_SIGTIMEDWAIT => "sigtimedwt",
        NR_FUTEX => "futex",
        NR_EPOLL_WAIT => "epoll_wait",
        NR_EPOLL_PWAIT => "epoll_pwt",
        NR_WAIT4 => "wait4",
        NR_WAITID => "waitid",
        NR_ACCEPT => "accept",
        NR_ACCEPT4 => "accept4",
        NR_EXECVE => "execve",
        NR_CLONE => "clone",
        NR_FORK => "fork",
        _ => return None,
    })
}

pub fn emit_syscall(nr: u32) {
    if nr == u32::MAX {
        klog::write_raw(b"none");
    } else if let Some(n) = syscall_name(nr) {
        klog::write_raw(n.as_bytes());
    } else {
        klog::write_raw(b"nr#");
        klog::write_dec_u64(nr as u64);
    }
}

pub fn col_syscall(nr: u32) {
    let mut buf = [b' '; 10];
    if nr == u32::MAX {
        let _ = copy_into(&mut buf, b"none");
    } else if let Some(n) = syscall_name(nr) {
        let _ = copy_into(&mut buf, n.as_bytes());
    } else {
        let mut tmp = [0u8; 10];
        let p = fmt_dec(nr as u64, &mut tmp);
        let mut w = copy_into(&mut buf, b"nr#");
        let mut i = 0;
        while w < buf.len() && i < (tmp.len() - p) {
            buf[w] = tmp[p + i];
            w += 1;
            i += 1;
        }
    }
    klog::write_raw(&buf);
}

pub fn col_dec(v: u64, width: usize) {
    let mut tmp = [0u8; 20];
    let start = fmt_dec(v, &mut tmp);
    let ndigits = tmp.len() - start;
    let mut i = ndigits;
    while i < width {
        klog::write_raw(b" ");
        i += 1;
    }
    klog::write_raw(&tmp[start..]);
}

pub fn col_str(s: &str, width: usize) {
    let b = s.as_bytes();
    let n = if b.len() > width { width } else { b.len() };
    klog::write_raw(&b[..n]);
    let mut i = n;
    while i < width {
        klog::write_raw(b" ");
        i += 1;
    }
}

pub fn fmt_dec(mut v: u64, buf: &mut [u8]) -> usize {
    let mut i = buf.len();
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
        return i;
    }
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    i
}

pub fn copy_into(dst: &mut [u8], src: &[u8]) -> usize {
    let n = if src.len() > dst.len() { dst.len() } else { src.len() };
    dst[..n].copy_from_slice(&src[..n]);
    n
}
