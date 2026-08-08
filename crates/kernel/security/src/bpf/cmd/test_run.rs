// `BPF_PROG_TEST_RUN` — run one loaded program against caller-supplied
// input and report what it returned.
//
// Only program types with a test-run implementation can be run this way;
// every other type is `-ENOTSUPP` (524), which reaches userspace verbatim
// even though it sits above the standard errno range.
//
// The write-back protocol is the subtle part: a short `data_size_out`
// clamps the copy and reports `-ENOSPC`, but the metadata — the real
// output size, the return value, the duration — is written anyway, so a
// caller that sized its buffer wrong still learns how big to make it.

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::super::attr::{self, Attr};
use super::super::uapi;
use super::super::user;
use super::super::BpfProgInode;
use super::objfd;
use super::skb_ctx;

/// Which test-run implementation a program type has, if any.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Runner {
    /// Runs against a `struct __sk_buff` built from caller-supplied bytes.
    Skb,
}

/// `prog->aux->ops->test_run`. A program type with no entry here is
/// `-ENOTSUPP`. # C: O(1)
pub(crate) fn runner_for(prog_type: u32) -> Option<Runner> {
    use uapi::prog_type as p;
    match prog_type {
        p::SOCKET_FILTER | p::CGROUP_SKB => Some(Runner::Skb),
        _ => None,
    }
}

/// A context buffer and its size must be supplied together or not at all,
/// in each direction independently. # C: O(1)
fn ctx_pairing_verdict(size: u32, ptr: u64) -> Result<(), Errno> {
    if (size != 0) != (ptr != 0) { return Err(Errno::Einval); }
    Ok(())
}

/// `bpf_check_uarg_tail_zero()`: a caller may pass a context longer than
/// this kernel's, but the excess must be zero — otherwise it is asking
/// for a field that does not exist here. # C: O(size)
fn ctx_tail_verdict(ptr: u64, expected: usize, actual: u32) -> Result<(), Errno> {
    if actual > uapi::PAGE_SIZE { return Err(Errno::E2big); }
    let actual = actual as usize;
    if actual <= expected { return Ok(()); }
    let tail = ptr.checked_add(expected as u64).ok_or(Errno::Efault)?;
    attr::tail_verdict(user::all_zero(tail, actual - expected)?)
}

/// Build the caller's context, or `None` when neither direction was
/// asked for. A context supplied only for output starts zeroed.
/// # C: O(ctx_size_in)
fn ctx_init(a: &Attr) -> Result<Option<[u8; skb_ctx::SIZE]>, Errno> {
    use uapi::off::test as o;
    let ctx_in = a.u64_at(o::CTX_IN);
    let ctx_out = a.u64_at(o::CTX_OUT);
    if ctx_in == 0 && ctx_out == 0 { return Ok(None); }
    let mut ctx = [0u8; skb_ctx::SIZE];
    if ctx_in != 0 {
        let size = a.u32_at(o::CTX_SIZE_IN);
        ctx_tail_verdict(ctx_in, skb_ctx::SIZE, size)?;
        let copy = core::cmp::min(skb_ctx::SIZE, size as usize);
        user::read_bytes(ctx_in, &mut ctx[..copy])?;
    }
    Ok(Some(ctx))
}

/// Copy the run's context back. A short `ctx_size_out` clamps the copy
/// and reports `-ENOSPC` while still recording the real size.
/// # C: O(ctx_size_out)
fn ctx_finish(a: &Attr, attr_ptr: u64, ctx: Option<&[u8; skb_ctx::SIZE]>) -> Result<i64, Errno> {
    use uapi::off::test as o;
    let Some(ctx) = ctx else { return Ok(0) };
    let ctx_out = a.u64_at(o::CTX_OUT);
    if ctx_out == 0 { return Ok(0); }
    let want = a.u32_at(o::CTX_SIZE_OUT) as usize;
    let short = want < skb_ctx::SIZE;
    let copy = core::cmp::min(want, skb_ctx::SIZE);
    user::write_bytes(ctx_out, &ctx[..copy])?;
    write_u32(attr_ptr, o::CTX_SIZE_OUT, skb_ctx::SIZE as u32)?;
    if short { Err(Errno::Enospc) } else { Ok(0) }
}

fn write_u32(attr_ptr: u64, offset: usize, value: u32) -> Result<(), Errno> {
    let at = attr_ptr.checked_add(offset as u64).ok_or(Errno::Efault)?;
    user::write_bytes(at, &value.to_ne_bytes())
}

/// `bpf_test_finish()`. `-ENOSPC` when the caller's output buffer was too
/// small for the frame, with every metadata field still written.
/// # C: O(bytes copied)
fn test_finish(
    a: &Attr,
    attr_ptr: u64,
    data: &[u8],
    retval: u32,
    duration: u32,
) -> Result<i64, Errno> {
    use uapi::off::test as o;
    let data_out = a.u64_at(o::DATA_OUT);
    let want = a.u32_at(o::DATA_SIZE_OUT);
    let size = data.len() as u32;
    let short = want != 0 && size > want;
    if data_out != 0 {
        let copy = if short { want as usize } else { data.len() };
        user::write_bytes(data_out, &data[..copy])?;
    }
    write_u32(attr_ptr, o::DATA_SIZE_OUT, size)?;
    write_u32(attr_ptr, o::RETVAL, retval)?;
    write_u32(attr_ptr, o::DURATION, duration)?;
    if short { Err(Errno::Enospc) } else { Ok(0) }
}

/// A zero `repeat` means one run. # C: O(1)
fn repeat_count(repeat: u32) -> u32 { if repeat == 0 { 1 } else { repeat } }

/// Flags, `cpu` and `batch_size` an skb-context run accepts: only the
/// checksum-completion flag, and neither of the two fields, which belong
/// to the live-frame runners. # C: O(1)
fn skb_flag_verdict(flags: u32, cpu: u32, batch_size: u32) -> Result<(), Errno> {
    if flags & !uapi::test_flags::SKB_MASK != 0 { return Err(Errno::Einval); }
    if cpu != 0 || batch_size != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// A frame shorter than a link-layer header is not one. # C: O(1)
fn skb_data_size_verdict(data_size_in: u32) -> Result<(), Errno> {
    if data_size_in < uapi::ETH_HLEN { return Err(Errno::Einval); }
    if data_size_in > uapi::TEST_RUN_DATA_MAX { return Err(Errno::Enomem); }
    Ok(())
}

/// `bpf_prog_test_run_skb()`. # C: O(repeat × instructions)
fn run_skb(a: &Attr, attr_ptr: u64, prog: &BpfProgInode) -> Result<i64, Errno> {
    use uapi::off::test as o;
    skb_flag_verdict(a.u32_at(o::FLAGS), a.u32_at(o::CPU), a.u32_at(o::BATCH_SIZE))?;
    let data_size_in = a.u32_at(o::DATA_SIZE_IN);
    skb_data_size_verdict(data_size_in)?;
    let mut ctx = ctx_init(a)?;
    let wire_len = match &ctx {
        Some(ctx) => skb_ctx::convert_in(ctx, data_size_in, data_size_in)?,
        None => data_size_in,
    };
    let packet: Vec<u8> = user::read_vec(a.u64_at(o::DATA_IN), data_size_in as usize)?;

    let run_ctx = skb_ctx::program_context(
        ctx.as_ref().unwrap_or(&[0u8; skb_ctx::SIZE]), data_size_in,
    );
    let mut run = run_ctx;
    let start = monotonic_ns();
    let mut retval = 0u32;
    for _ in 0..repeat_count(a.u32_at(o::REPEAT)) {
        run = run_ctx;
        retval = crate::bpf_interp::run_program_with_state(
            prog, &run, &packet, &[], &mut crate::bpf_interp::HelperState::default(),
        ).ok_or(Errno::Einval)? as u32;
    }
    let duration = duration_per_run(
        monotonic_ns().wrapping_sub(start), repeat_count(a.u32_at(o::REPEAT)),
    );

    if let Some(ctx) = ctx.as_mut() {
        skb_ctx::convert_out(ctx, &run, data_size_in, wire_len);
    }
    test_finish(a, attr_ptr, &packet, retval, duration)?;
    ctx_finish(a, attr_ptr, ctx.as_ref())
}

/// Monotonic nanoseconds; hosted builds have no timer, so a run there
/// reports a zero duration. # C: O(1)
fn monotonic_ns() -> u64 {
    #[cfg(target_os = "oxide-kernel")]
    { sched::live::timer_list::now_ns() }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Average nanoseconds per run, which is what the command reports.
/// # C: O(1)
fn duration_per_run(total_ns: u64, repeat: u32) -> u32 {
    let repeat = core::cmp::max(repeat, 1) as u64;
    (total_ns / repeat).min(u32::MAX as u64) as u32
}

/// `bpf_prog_test_run()`. No capability of its own: the right to run a
/// program is holding its descriptor. # C: O(repeat × instructions)
pub(in super::super) fn test_run(a: &Attr, attr_ptr: u64) -> Result<i64, Errno> {
    use uapi::off::test as o;
    attr::check_attr(a, o::LAST_END)?;
    ctx_pairing_verdict(a.u32_at(o::CTX_SIZE_IN), a.u64_at(o::CTX_IN))?;
    ctx_pairing_verdict(a.u32_at(o::CTX_SIZE_OUT), a.u64_at(o::CTX_OUT))?;
    let inode = objfd::prog_from_fd(a.u32_at(o::PROG_FD))?;
    let prog = inode.private::<BpfProgInode>().ok_or(Errno::Einval)?;
    match runner_for(prog.prog_type) {
        Some(Runner::Skb) => run_skb(a, attr_ptr, prog),
        None => Err(Errno::Enotsupp),
    }
}

#[cfg(test)]
#[path = "test_run/tests.rs"]
mod tests;
