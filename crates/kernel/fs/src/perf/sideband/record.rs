// Side-band `PERF_RECORD_*` byte layout — `perf_event_mmap_output`,
// `perf_event_comm_output`, `perf_event_task_output` and
// `perf_event_switch_output`.
//
// Pure over explicit values, like `super::super::sample`: the field ORDER is
// the ABI a consumer decodes with, so the tests assert exact bytes.

use super::super::sample::{push_sample_id, RecordBuf, SampleValues};
use super::super::uapi::record;

/// Ceiling on the NUL-terminated, u64-padded name a `PERF_RECORD_MMAP*` or
/// `PERF_RECORD_COMM` carries. The reference builds the name into a page-sized
/// scratch buffer; oxide builds records on the stack, so a longer name is
/// truncated (and still NUL-terminated) rather than dropping the record — a
/// consumer that cannot resolve one over-long path is strictly better off than
/// one missing the mapping entirely.
pub const NAME_MAX: usize = 256;

/// Stack budget for a side-band record. The largest form is `PERF_RECORD_MMAP2`:
/// an 8-byte header, `{pid,tid}`, `addr`/`len`/`pgoff`, the 32-byte identity
/// block, `prot`/`flags`, the padded name and the 48-byte `sample_id` trailer.
/// Rounded up to the next multiple of 8 with room to spare. These emitters are
/// reachable from `execve` and `mmap(2)` — the deepest paths in the kernel — so
/// they must NOT carry the sample path's 1 KiB buffer; doing so cost 472 B of
/// the boot chain's stack-depth budget.
pub const SIDEBAND_MAX: usize = 8 + 8 + 24 + 32 + 8 + NAME_MAX + 48;

/// The buffer every side-band record is built in.
pub type SbBuf = RecordBuf<SIDEBAND_MAX>;

/// `PERF_RECORD_MISC_MMAP_DATA` / `_COMM_EXEC` / `_SWITCH_OUT` — one bit,
/// reused per record type.
pub const MISC_MMAP_DATA: u16 = 1 << 13;
pub const MISC_COMM_EXEC: u16 = 1 << 13;
pub const MISC_SWITCH_OUT: u16 = 1 << 13;
/// `PERF_RECORD_MISC_SWITCH_OUT_PREEMPT`.
pub const MISC_SWITCH_OUT_PREEMPT: u16 = 1 << 14;

/// One mapping, as `perf_event_mmap_event` describes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmapInfo<'a> {
    pub pid:   u32,
    pub tid:   u32,
    pub addr:  u64,
    pub len:   u64,
    pub pgoff: u64,
    /// `MMAP2`-only device/inode identity.
    pub maj:   u32,
    pub min:   u32,
    pub ino:   u64,
    pub ino_generation: u64,
    /// `PROT_*` and `MAP_*` as the caller passed them, `MMAP2`-only.
    pub prot:  u32,
    pub flags: u32,
    /// `vma->vm_flags & VM_EXEC` — selects which events want this record and
    /// whether `PERF_RECORD_MISC_MMAP_DATA` is set.
    pub executable: bool,
    pub name:  &'a [u8],
}

/// Append `name`, NUL-terminated and zero-padded to a u64 boundary — the
/// reference's `ALIGN(strlen(name) + 1, sizeof(u64))`. # C: O(name)
fn push_name(r: &mut SbBuf, name: &[u8]) {
    let n = core::cmp::min(name.len(), NAME_MAX - 1);
    // A name is a path or a comm; an embedded NUL would end it early, so the
    // truncation point is the first NUL if there is one.
    let n = name[..n].iter().position(|&c| c == 0).unwrap_or(n);
    let padded = (n + 1).next_multiple_of(8);
    r.bytes(&name[..n]);
    for _ in n..padded { r.byte(0); }
}

/// `perf_event_mmap_output`. `mmap2` selects the augmented record: the
/// reference emits the SAME event as `PERF_RECORD_MMAP2` with the device,
/// inode and protection fields spliced between `pgoff` and the filename.
/// # C: O(name)
pub fn mmap_record(sample_type: u64, sample_id_all: bool, mmap2: bool,
                   m: &MmapInfo, v: &SampleValues) -> Option<SbBuf>
{
    let misc = if m.executable { 0 } else { MISC_MMAP_DATA };
    let ty = if mmap2 { record::MMAP2 } else { record::MMAP };
    let mut r = SbBuf::new(ty, misc);
    r.pair32(m.pid, m.tid);
    r.u64(m.addr);
    r.u64(m.len);
    r.u64(m.pgoff);
    if mmap2 {
        r.u32(m.maj);
        r.u32(m.min);
        r.u64(m.ino);
        r.u64(m.ino_generation);
        r.u32(m.prot);
        r.u32(m.flags);
    }
    push_name(&mut r, m.name);
    if sample_id_all { push_sample_id(&mut r, sample_type, v); }
    r.finish()
}

/// `perf_event_comm_output`. `exec` sets `PERF_RECORD_MISC_COMM_EXEC`, which
/// is how a consumer tells a `prctl(PR_SET_NAME)` rename from an `execve`.
/// # C: O(name)
pub fn comm_record(sample_type: u64, sample_id_all: bool, exec: bool,
                   pid: u32, tid: u32, comm: &[u8], v: &SampleValues)
    -> Option<SbBuf>
{
    let mut r = SbBuf::new(record::COMM, if exec { MISC_COMM_EXEC } else { 0 });
    r.pair32(pid, tid);
    push_name(&mut r, comm);
    if sample_id_all { push_sample_id(&mut r, sample_type, v); }
    r.finish()
}

/// `PERF_RECORD_THROTTLE` and `PERF_RECORD_UNTHROTTLE` share one layout and
/// differ only in the header type. The body is `{u64 time; u64 id;
/// u64 stream_id;}`; `id` is the group's primary id and `stream_id` this
/// event's own, so a group's throttle names the leader while still identifying
/// the member stream.
///
/// A consumer that never sees this record cannot distinguish a throttled event
/// from an idle one, so it is emitted even when nothing else about the event
/// changed. # C: O(1)
pub fn throttle_record(enable: bool, sample_type: u64, sample_id_all: bool,
                       v: &SampleValues) -> Option<SbBuf>
{
    let ty = if enable { record::UNTHROTTLE } else { record::THROTTLE };
    let mut r = SbBuf::new(ty, 0);
    r.u64(v.time);
    r.u64(v.id);
    r.u64(v.stream_id);
    if sample_id_all { push_sample_id(&mut r, sample_type, v); }
    r.finish()
}

/// `PERF_RECORD_READ` — `{u32 pid; u32 tid;}` followed by the same
/// `read_format` body a `read(2)` on the event returns.
///
/// Emitted for an `attr.inherit_stat` event when the task that inherited it
/// exits, so a consumer can attribute that child's final count to the child
/// rather than only seeing it folded into the parent's total.
/// # C: O(read_payload)
pub fn read_record<const N: usize>(sample_type: u64, sample_id_all: bool,
                                   pid: u32, tid: u32, read_payload: &[u8],
                                   v: &SampleValues) -> Option<RecordBuf<N>>
{
    let mut r = RecordBuf::<N>::new(record::READ, 0);
    r.pair32(pid, tid);
    r.bytes(read_payload);
    if sample_id_all { push_sample_id(&mut r, sample_type, v); }
    r.finish()
}

/// `perf_event_task_output` — `PERF_RECORD_FORK` and `PERF_RECORD_EXIT` share
/// one layout, differing only in the header type. # C: O(1)
pub fn task_record(ty: u32, sample_type: u64, sample_id_all: bool,
                   pid: u32, ppid: u32, tid: u32, ptid: u32, time: u64,
                   v: &SampleValues) -> Option<SbBuf>
{
    let mut r = SbBuf::new(ty, 0);
    r.pair32(pid, ppid);
    r.pair32(tid, ptid);
    r.u64(time);
    if sample_id_all { push_sample_id(&mut r, sample_type, v); }
    r.finish()
}

/// `perf_event_switch_output`. A task-scoped event gets the bare
/// `PERF_RECORD_SWITCH`; only a CPU-wide one may see the other side's identity,
/// which is what `PERF_RECORD_SWITCH_CPU_WIDE` carries.
/// # C: O(1)
pub fn switch_record(sample_type: u64, sample_id_all: bool, cpu_wide: bool,
                     switching_out: bool, preempt: bool,
                     next_prev_pid: u32, next_prev_tid: u32, v: &SampleValues)
    -> Option<SbBuf>
{
    let mut misc = 0u16;
    if switching_out {
        misc |= MISC_SWITCH_OUT;
        if preempt { misc |= MISC_SWITCH_OUT_PREEMPT; }
    }
    let ty = if cpu_wide { record::SWITCH_CPU_WIDE } else { record::SWITCH };
    let mut r = SbBuf::new(ty, misc);
    if cpu_wide { r.pair32(next_prev_pid, next_prev_tid); }
    if sample_id_all { push_sample_id(&mut r, sample_type, v); }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::uapi::sample;
    use alloc::vec::Vec;

    fn vals() -> SampleValues {
        SampleValues { id: 0x11, stream_id: 0x22, ip: 0, pid: 5, tid: 6,
                       time: 0x4444, addr: 0, cpu: 1, period: 0 }
    }

    fn u64s(b: &[u8]) -> Vec<u64> {
        b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
    }

    fn info<'a>(name: &'a [u8], exec: bool) -> MmapInfo<'a> {
        MmapInfo { pid: 5, tid: 6, addr: 0x40_0000, len: 0x2000, pgoff: 0x1000,
                   maj: 8, min: 3, ino: 99, ino_generation: 7,
                   prot: 5, flags: 2, executable: exec, name }
    }

    /// `PERF_RECORD_MMAP` is pid/tid, addr, len, pgoff, then the padded name.
    #[test]
    fn the_mmap_record_is_the_reference_field_order() {
        let r = mmap_record(0, false, false, &info(b"/lib/libc.so", true), &vals()).unwrap();
        let b = r.as_slice();
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), record::MMAP);
        assert_eq!(u16::from_le_bytes(b[4..6].try_into().unwrap()), 0, "executable: no DATA bit");
        assert_eq!(u16::from_le_bytes(b[6..8].try_into().unwrap()) as usize, b.len());
        let body = &b[record::HEADER_BYTES..];
        assert_eq!(u64s(&body[..32]), alloc::vec![
            6u64 << 32 | 5,  // {pid, tid}
            0x40_0000,       // addr
            0x2000,          // len
            0x1000,          // pgoff
        ]);
        // The name is NUL-terminated and padded out to a u64 boundary.
        assert_eq!(&body[32..44], b"/lib/libc.so");
        assert_eq!(&body[44..48], b"\0\0\0\0");
        assert_eq!(body.len(), 48);
    }

    /// `MMAP2` splices maj/min/ino/ino_generation/prot/flags in before the
    /// name; everything else, including the name's padding, is identical.
    #[test]
    fn mmap2_adds_the_identity_fields_between_pgoff_and_the_name() {
        let i = info(b"/lib/libc.so", true);
        let plain = mmap_record(0, false, false, &i, &vals()).unwrap();
        let two   = mmap_record(0, false, true, &i, &vals()).unwrap();
        assert_eq!(u32::from_le_bytes(two.as_slice()[0..4].try_into().unwrap()), record::MMAP2);
        assert_eq!(two.len(), plain.len() + 32);
        let body = &two.as_slice()[record::HEADER_BYTES..];
        assert_eq!(u32::from_le_bytes(body[32..36].try_into().unwrap()), 8);  // maj
        assert_eq!(u32::from_le_bytes(body[36..40].try_into().unwrap()), 3);  // min
        assert_eq!(u64::from_le_bytes(body[40..48].try_into().unwrap()), 99); // ino
        assert_eq!(u64::from_le_bytes(body[48..56].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(body[56..60].try_into().unwrap()), 5);  // prot
        assert_eq!(u32::from_le_bytes(body[60..64].try_into().unwrap()), 2);  // flags
        assert_eq!(&body[64..76], b"/lib/libc.so");
    }

    /// A non-executable mapping is flagged `PERF_RECORD_MISC_MMAP_DATA`, which
    /// is how a consumer knows it is not a code mapping to symbolise.
    #[test]
    fn a_data_mapping_carries_the_mmap_data_misc_bit() {
        let r = mmap_record(0, false, false, &info(b"/tmp/heap", false), &vals()).unwrap();
        assert_eq!(u16::from_le_bytes(r.as_slice()[4..6].try_into().unwrap()), MISC_MMAP_DATA);
    }

    /// A name is padded so that the record — and therefore every field after
    /// it — stays u64 aligned, at EVERY length.
    #[test]
    fn every_name_length_pads_to_a_u64_boundary_with_a_terminator() {
        for n in 0..40usize {
            let name: Vec<u8> = core::iter::repeat(b'a').take(n).collect();
            let r = mmap_record(0, false, false, &info(&name, true), &vals()).unwrap();
            assert_eq!(r.len() % 8, 0, "len {n}");
            let body = &r.as_slice()[record::HEADER_BYTES + 32..];
            assert_eq!(body.len(), (n + 1).next_multiple_of(8), "len {n}");
            assert_eq!(body[n], 0, "len {n}: terminated");
        }
        // An over-long name is truncated, never allowed to overrun the record.
        let long: Vec<u8> = core::iter::repeat(b'z').take(4096).collect();
        let r = mmap_record(0, false, false, &info(&long, true), &vals()).unwrap();
        let body = &r.as_slice()[record::HEADER_BYTES + 32..];
        assert_eq!(body.len(), NAME_MAX);
        assert_eq!(body[NAME_MAX - 1], 0);
    }

    #[test]
    fn the_comm_record_distinguishes_an_exec_from_a_rename() {
        let rename = comm_record(0, false, false, 5, 6, b"bash", &vals()).unwrap();
        assert_eq!(u32::from_le_bytes(rename.as_slice()[0..4].try_into().unwrap()), record::COMM);
        assert_eq!(u16::from_le_bytes(rename.as_slice()[4..6].try_into().unwrap()), 0);
        assert_eq!(&rename.as_slice()[16..20], b"bash");
        let exec = comm_record(0, false, true, 5, 6, b"bash", &vals()).unwrap();
        assert_eq!(u16::from_le_bytes(exec.as_slice()[4..6].try_into().unwrap()), MISC_COMM_EXEC);
    }

    /// FORK and EXIT are `{pid, ppid}, {tid, ptid}, time` — the pairs are NOT
    /// `{pid, tid}`, which is the mistake a consumer would decode as swapped
    /// process and parent ids.
    #[test]
    fn fork_and_exit_share_one_layout_and_pair_pid_with_ppid() {
        for ty in [record::FORK, record::EXIT] {
            let r = task_record(ty, 0, false, 100, 50, 101, 51, 0x9999, &vals()).unwrap();
            let b = r.as_slice();
            assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), ty);
            assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 100);  // pid
            assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()), 50);  // ppid
            assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), 101); // tid
            assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 51);  // ptid
            assert_eq!(u64::from_le_bytes(b[24..32].try_into().unwrap()), 0x9999);
            assert_eq!(b.len(), 32);
        }
    }

    /// A task-scoped event gets a header-only `PERF_RECORD_SWITCH`; only a
    /// CPU-wide one may see the other task's identity.
    #[test]
    fn only_a_cpu_wide_switch_record_names_the_other_task() {
        let task = switch_record(0, false, false, true, false, 7, 8, &vals()).unwrap();
        assert_eq!(task.len(), record::HEADER_BYTES);
        assert_eq!(u32::from_le_bytes(task.as_slice()[0..4].try_into().unwrap()), record::SWITCH);
        assert_eq!(u16::from_le_bytes(task.as_slice()[4..6].try_into().unwrap()), MISC_SWITCH_OUT);

        let wide = switch_record(0, false, true, false, false, 7, 8, &vals()).unwrap();
        assert_eq!(u32::from_le_bytes(wide.as_slice()[0..4].try_into().unwrap()),
                   record::SWITCH_CPU_WIDE);
        assert_eq!(u16::from_le_bytes(wide.as_slice()[4..6].try_into().unwrap()), 0,
                   "switching in carries no OUT bit");
        assert_eq!(u32::from_le_bytes(wide.as_slice()[8..12].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(wide.as_slice()[12..16].try_into().unwrap()), 8);

        let preempted = switch_record(0, false, false, true, true, 0, 0, &vals()).unwrap();
        assert_eq!(u16::from_le_bytes(preempted.as_slice()[4..6].try_into().unwrap()),
                   MISC_SWITCH_OUT | MISC_SWITCH_OUT_PREEMPT);
    }

    /// Every side-band record carries the same `sample_id` trailer a sample
    /// does when `attr.sample_id_all` is set — without it a consumer cannot
    /// attribute the record to a stream.
    #[test]
    fn sample_id_all_appends_the_trailer_to_every_side_band_record() {
        let st = sample::TID | sample::TIME | sample::ID;
        let v = vals();
        let bare = comm_record(st, false, false, 5, 6, b"sh", &v).unwrap().len();
        let with = comm_record(st, true, false, 5, 6, b"sh", &v).unwrap();
        assert_eq!(with.len(), bare + 24);
        assert_eq!(u64s(&with.as_slice()[bare..]),
                   alloc::vec![6u64 << 32 | 5, 0x4444, 0x11]);

        for r in [task_record(record::FORK, st, true, 1, 2, 3, 4, 9, &v).unwrap(),
                  switch_record(st, true, false, false, false, 0, 0, &v).unwrap(),
                  mmap_record(st, true, true, &info(b"x", true), &v).unwrap()] {
            assert_eq!(u16::from_le_bytes(r.as_slice()[6..8].try_into().unwrap()) as usize,
                       r.len(), "header.size counts the trailer");
        }
    }
}
