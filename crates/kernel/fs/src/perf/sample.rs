// `PERF_RECORD_*` byte layout — `perf_output_sample`, `__perf_event__output_id_sample`
// and the `PERF_RECORD_LOST` prologue `__perf_output_begin` prepends.
//
// Pure over explicit values and allocation-free: a record is built into a
// fixed `RecordBuf` so the emit path (which runs in fault context) never
// allocates. Field ORDER here is the ABI; the tests assert exact bytes so a
// reordering cannot pass.

use super::uapi::{record, sample};

/// Ceiling on one formatted record. Every field this kernel emits is a fixed
/// 8 or 16 bytes, so the only variable part is the `PERF_SAMPLE_READ` payload
/// (`read_size`, itself capped at `counter::READ_SIZE_MAX`). A record that
/// does not fit is dropped and counted lost rather than truncated — a
/// truncated record would desynchronise the whole ring.
pub const MAX_RECORD: usize = 1024;

/// A record under construction. `push_*` silently stops at `N` and sets
/// `overflow`, which `finish` reports.
///
/// `N` is a stack budget, not an ABI limit: a `PERF_RECORD_SAMPLE` needs the
/// full [`MAX_RECORD`] because `PERF_SAMPLE_READ`'s payload scales with the
/// group, while a side-band record's largest form is a fixed few hundred bytes.
/// The side-band emitters are reachable from `execve` and `mmap(2)`, i.e. from
/// the deepest paths in the kernel, so they carry the smaller buffer — a 1 KiB
/// array there cost 472 B on the boot chain's stack-depth budget.
pub struct RecordBuf<const N: usize = MAX_RECORD> {
    buf:      [u8; N],
    len:      usize,
    overflow: bool,
}

impl<const N: usize> RecordBuf<N> {
    /// # C: O(1)
    pub fn new(ty: u32, misc: u16) -> RecordBuf<N> {
        let mut r = RecordBuf { buf: [0u8; N], len: 0, overflow: false };
        r.u32(ty);
        r.u16(misc);
        r.u16(0); // header.size — patched by `finish`
        r
    }
    fn raw(&mut self, b: &[u8]) {
        if self.len + b.len() > N { self.overflow = true; return; }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }
    /// # C: O(1)
    pub fn byte(&mut self, v: u8) { self.raw(&[v]); }
    /// # C: O(1)
    pub fn u16(&mut self, v: u16) { self.raw(&v.to_le_bytes()); }
    /// # C: O(1)
    pub fn u32(&mut self, v: u32) { self.raw(&v.to_le_bytes()); }
    /// # C: O(1)
    pub fn u64(&mut self, v: u64) { self.raw(&v.to_le_bytes()); }
    /// A `{u32, u32}` pair — the encoding `tid_entry` and `cpu_entry` use.
    /// # C: O(1)
    pub fn pair32(&mut self, a: u32, b: u32) { self.u32(a); self.u32(b); }
    /// # C: O(1)
    pub fn bytes(&mut self, b: &[u8]) { self.raw(b); }

    /// Patch `header.size` and hand back the record, or `None` if it did not
    /// fit. Records are always a multiple of 8 bytes, so a record whose length
    /// is not is a layout bug and is refused rather than shipped.
    /// # C: O(1)
    pub fn finish(mut self) -> Option<RecordBuf<N>> {
        if self.overflow || self.len > u16::MAX as usize || self.len % 8 != 0 { return None; }
        let size = self.len as u16;
        self.buf[6..8].copy_from_slice(&size.to_le_bytes());
        Some(self)
    }
    /// # C: O(1)
    pub fn as_slice(&self) -> &[u8] { &self.buf[..self.len] }
    /// # C: O(1)
    pub fn len(&self) -> usize { self.len }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.len == 0 }
}

/// The identity fields every record can carry — `struct perf_sample_data`'s
/// `tid_entry`/`time`/`id`/`stream_id`/`cpu_entry`, plus the sample-only
/// `ip`/`addr`/`period`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SampleValues {
    /// `primary_event_id(event)` — the group leader's id, what both
    /// `PERF_SAMPLE_ID` and `PERF_SAMPLE_IDENTIFIER` report.
    pub id:        u64,
    /// `event->id`, distinct from `id` for a group member.
    pub stream_id: u64,
    pub ip:        u64,
    pub pid:       u32,
    pub tid:       u32,
    pub time:      u64,
    pub addr:      u64,
    pub cpu:       u32,
    pub period:    u64,
}

/// `__perf_event_header__init_id`'s contribution to `event->id_header_size`:
/// the byte cost of the `struct sample_id` trailer. # C: O(1)
pub fn sample_id_size(sample_type: u64) -> usize {
    let mut n = 0;
    if sample_type & sample::TID       != 0 { n += 8; }
    if sample_type & sample::TIME      != 0 { n += 8; }
    if sample_type & sample::ID        != 0 { n += 8; }
    if sample_type & sample::STREAM_ID != 0 { n += 8; }
    if sample_type & sample::CPU       != 0 { n += 8; }
    if sample_type & sample::IDENTIFIER != 0 { n += 8; }
    n
}

/// `__perf_event__output_id_sample` — the trailer appended to every NON-sample
/// record when `attr.sample_id_all` is set. Its field order differs from the
/// sample body's (no IP/ADDR/PERIOD, and IDENTIFIER comes LAST rather than
/// first), which is the whole point of the separate writer. # C: O(1)
pub fn push_sample_id<const N: usize>(r: &mut RecordBuf<N>, sample_type: u64, v: &SampleValues) {
    if sample_type & sample::TID       != 0 { r.pair32(v.pid, v.tid); }
    if sample_type & sample::TIME      != 0 { r.u64(v.time); }
    if sample_type & sample::ID        != 0 { r.u64(v.id); }
    if sample_type & sample::STREAM_ID != 0 { r.u64(v.stream_id); }
    if sample_type & sample::CPU       != 0 { r.pair32(v.cpu, 0); }
    if sample_type & sample::IDENTIFIER != 0 { r.u64(v.id); }
}

/// `perf_output_sample` — a complete `PERF_RECORD_SAMPLE`.
///
/// `read_payload` is the already-formatted `PERF_SAMPLE_READ` body (the same
/// bytes `read(2)` returns, per `counter::format_one`/`format_group`); it is
/// ignored unless `PERF_SAMPLE_READ` is set.
///
/// Fields this kernel has no source for are emitted in the reference's
/// "PMU supplied nothing" encoding — an empty callchain/branch stack
/// (`u64 nr = 0`), a null raw record (`{u32 size = 4; u32 data = 0}`), a
/// `PERF_SAMPLE_REGS_ABI_NONE` register dump (`u64 abi = 0`) and a zero-length
/// user-stack dump — so the record's SHAPE is always exactly what a consumer
/// computes from `sample_type`.
/// # C: O(sample_type popcount + read_payload)
pub fn sample_record(sample_type: u64, misc: u16, v: &SampleValues, read_payload: &[u8])
    -> Option<RecordBuf>
{
    let mut r = RecordBuf::new(record::SAMPLE, misc);
    if sample_type & sample::IDENTIFIER != 0 { r.u64(v.id); }
    if sample_type & sample::IP         != 0 { r.u64(v.ip); }
    if sample_type & sample::TID        != 0 { r.pair32(v.pid, v.tid); }
    if sample_type & sample::TIME       != 0 { r.u64(v.time); }
    if sample_type & sample::ADDR       != 0 { r.u64(v.addr); }
    if sample_type & sample::ID         != 0 { r.u64(v.id); }
    if sample_type & sample::STREAM_ID  != 0 { r.u64(v.stream_id); }
    if sample_type & sample::CPU        != 0 { r.pair32(v.cpu, 0); }
    if sample_type & sample::PERIOD     != 0 { r.u64(v.period); }
    if sample_type & sample::READ       != 0 { r.bytes(read_payload); }
    // No kernel unwinder is wired to the software-event sample point, so the
    // callchain is empty rather than absent — dropping the field would shift
    // every later field.
    if sample_type & sample::CALLCHAIN  != 0 { r.u64(0); }
    // `data->raw == NULL`: `{u32 size = sizeof(u32); u32 data = 0;}`.
    if sample_type & sample::RAW        != 0 { r.u32(4); r.u32(0); }
    if sample_type & sample::BRANCH_STACK != 0 { r.u64(0); }
    if sample_type & sample::REGS_USER  != 0 { r.u64(0); }
    if sample_type & sample::STACK_USER != 0 { r.u64(0); }
    if sample_type & sample::WEIGHT_TYPE != 0 { r.u64(0); }
    if sample_type & sample::DATA_SRC   != 0 { r.u64(0); }
    if sample_type & sample::TRANSACTION != 0 { r.u64(0); }
    if sample_type & sample::REGS_INTR  != 0 { r.u64(0); }
    if sample_type & sample::PHYS_ADDR  != 0 { r.u64(0); }
    if sample_type & sample::CGROUP     != 0 { r.u64(0); }
    if sample_type & sample::DATA_PAGE_SIZE != 0 { r.u64(0); }
    if sample_type & sample::CODE_PAGE_SIZE != 0 { r.u64(0); }
    if sample_type & sample::AUX        != 0 { r.u64(0); }
    r.finish()
}

/// The `PERF_RECORD_LOST` `__perf_output_begin` prepends once `rb->lost` is
/// nonzero: `{header; u64 id; u64 lost;}` plus the `sample_id` trailer.
/// # C: O(1)
pub fn lost_record<const N: usize>(sample_type: u64, sample_id_all: bool, lost: u64,
                                   v: &SampleValues) -> Option<RecordBuf<N>>
{
    let mut r = RecordBuf::new(record::LOST, 0);
    r.u64(v.id);
    r.u64(lost);
    if sample_id_all { push_sample_id(&mut r, sample_type, v); }
    r.finish()
}

/// Byte cost of a `PERF_RECORD_SAMPLE` before it is built, for the caller that
/// must reserve space first. # C: O(1)
pub fn sample_size(sample_type: u64, read_payload_len: usize) -> usize {
    let mut n = record::HEADER_BYTES;
    // Every emitted field is 8 bytes wide (the `{u32,u32}` pairs included).
    for bit in [sample::IDENTIFIER, sample::IP, sample::TID, sample::TIME, sample::ADDR,
                sample::ID, sample::STREAM_ID, sample::CPU, sample::PERIOD,
                sample::CALLCHAIN, sample::RAW, sample::BRANCH_STACK, sample::REGS_USER,
                sample::STACK_USER, sample::DATA_SRC, sample::TRANSACTION,
                sample::REGS_INTR, sample::PHYS_ADDR, sample::CGROUP,
                sample::DATA_PAGE_SIZE, sample::CODE_PAGE_SIZE, sample::AUX] {
        if sample_type & bit != 0 { n += 8; }
    }
    if sample_type & sample::WEIGHT_TYPE != 0 { n += 8; }
    if sample_type & sample::READ != 0 { n += read_payload_len; }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn vals() -> SampleValues {
        SampleValues { id: 0x1111, stream_id: 0x2222, ip: 0xffff_8000_dead_beef,
                       pid: 0x30, tid: 0x31, time: 0x4444, addr: 0x5555,
                       cpu: 3, period: 0x6666 }
    }

    fn u64s(b: &[u8]) -> Vec<u64> {
        b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect()
    }

    #[test]
    fn header_is_type_misc_size_and_size_counts_the_whole_record() {
        let r = sample_record(sample::IP, record::MISC_USER, &vals(), &[]).unwrap();
        let b = r.as_slice();
        assert_eq!(b.len(), 16);
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), record::SAMPLE);
        assert_eq!(u16::from_le_bytes(b[4..6].try_into().unwrap()), record::MISC_USER);
        assert_eq!(u16::from_le_bytes(b[6..8].try_into().unwrap()), 16);
        assert_eq!(u64::from_le_bytes(b[8..16].try_into().unwrap()), 0xffff_8000_dead_beef);
    }

    /// The exact-byte layout check: every field this kernel populates, in the
    /// reference's order. Reordering ANY pair of these fails here.
    #[test]
    fn sample_field_order_is_the_reference_order() {
        let st = sample::IDENTIFIER | sample::IP | sample::TID | sample::TIME
               | sample::ADDR | sample::ID | sample::STREAM_ID | sample::CPU
               | sample::PERIOD;
        let v = vals();
        let r = sample_record(st, record::MISC_USER, &v, &[]).unwrap();
        let body = &r.as_slice()[record::HEADER_BYTES..];
        assert_eq!(body.len(), 9 * 8);
        assert_eq!(u64s(body), alloc::vec![
            0x1111,                                  // IDENTIFIER
            0xffff_8000_dead_beef,                   // IP
            0x31u64 << 32 | 0x30,                    // TID: {pid, tid}
            0x4444,                                  // TIME
            0x5555,                                  // ADDR
            0x1111,                                  // ID (same primary id)
            0x2222,                                  // STREAM_ID
            3,                                       // CPU: {cpu, res = 0}
            0x6666,                                  // PERIOD
        ]);
    }

    #[test]
    fn read_payload_lands_between_period_and_callchain() {
        let st = sample::PERIOD | sample::READ | sample::CALLCHAIN;
        let payload = 0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes();
        let r = sample_record(st, 0, &vals(), &payload).unwrap();
        let body = u64s(&r.as_slice()[record::HEADER_BYTES..]);
        assert_eq!(body, alloc::vec![0x6666, 0xAAAA_BBBB_CCCC_DDDD, 0]);
    }

    #[test]
    fn unsourced_fields_emit_the_reference_empty_encodings() {
        let st = sample::CALLCHAIN | sample::RAW | sample::BRANCH_STACK
               | sample::REGS_USER | sample::STACK_USER | sample::WEIGHT
               | sample::DATA_SRC | sample::TRANSACTION | sample::REGS_INTR
               | sample::PHYS_ADDR | sample::DATA_PAGE_SIZE | sample::CODE_PAGE_SIZE
               | sample::AUX;
        let r = sample_record(st, 0, &vals(), &[]).unwrap();
        let body = &r.as_slice()[record::HEADER_BYTES..];
        assert_eq!(body.len(), 13 * 8);
        // A null raw record is `{u32 size = 4; u32 data = 0}`, not a zero u64.
        assert_eq!(u32::from_le_bytes(body[8..12].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(body[12..16].try_into().unwrap()), 0);
        // Everything else is a zero u64 (empty callchain, ABI_NONE regs, ...).
        for (i, w) in u64s(body).iter().enumerate() {
            if i == 1 { continue; }
            assert_eq!(*w, 0, "field {i}");
        }
        // WEIGHT and WEIGHT_STRUCT share one slot.
        let both = sample_record(sample::WEIGHT_STRUCT, 0, &vals(), &[]).unwrap();
        assert_eq!(both.len(), record::HEADER_BYTES + 8);
    }

    #[test]
    fn sample_size_matches_the_record_it_predicts() {
        for st in [0u64, sample::IP, sample::IP | sample::TID | sample::TIME,
                   sample::MAX - 1 & !sample::READ, sample::CPU | sample::PERIOD] {
            let r = sample_record(st, 0, &vals(), &[]).unwrap();
            assert_eq!(sample_size(st, 0), r.len(), "sample_type {st:#x}");
        }
        let payload = [0u8; 24];
        let st = sample::READ | sample::IP;
        let r = sample_record(st, 0, &vals(), &payload).unwrap();
        assert_eq!(sample_size(st, payload.len()), r.len());
    }

    /// `sample_id`'s order is NOT the sample body's: IDENTIFIER moves to the
    /// end and IP/ADDR/PERIOD are absent.
    #[test]
    fn sample_id_trailer_order_differs_from_the_sample_body() {
        let st = sample::IDENTIFIER | sample::IP | sample::TID | sample::TIME
               | sample::ID | sample::STREAM_ID | sample::CPU | sample::PERIOD;
        let v = vals();
        let mut r = RecordBuf::<MAX_RECORD>::new(record::LOST, 0);
        push_sample_id(&mut r, st, &v);
        let body = u64s(&r.as_slice()[record::HEADER_BYTES..]);
        assert_eq!(body, alloc::vec![
            0x31u64 << 32 | 0x30, // TID
            0x4444,               // TIME
            0x1111,               // ID
            0x2222,               // STREAM_ID
            3,                    // CPU
            0x1111,               // IDENTIFIER last
        ]);
        assert_eq!(sample_id_size(st), 6 * 8);
    }

    #[test]
    fn lost_record_is_id_then_count_then_optional_trailer() {
        let v = vals();
        let bare = lost_record::<MAX_RECORD>(sample::TID, false, 9, &v).unwrap();
        assert_eq!(bare.len(), record::HEADER_BYTES + 16);
        let b = bare.as_slice();
        assert_eq!(u32::from_le_bytes(b[0..4].try_into().unwrap()), record::LOST);
        assert_eq!(u64s(&b[record::HEADER_BYTES..]), alloc::vec![0x1111, 9]);

        let with_id = lost_record::<MAX_RECORD>(sample::TID | sample::TIME, true, 9, &v).unwrap();
        assert_eq!(with_id.len(), record::HEADER_BYTES + 16 + 16);
        assert_eq!(u64s(&with_id.as_slice()[record::HEADER_BYTES..]),
                   alloc::vec![0x1111, 9, 0x31u64 << 32 | 0x30, 0x4444]);
    }

    #[test]
    fn a_record_that_would_exceed_the_buffer_is_refused_not_truncated() {
        let big = [0u8; MAX_RECORD];
        assert!(sample_record(sample::READ, 0, &vals(), &big).is_none());
        // Right at the boundary it still succeeds.
        let fits = [0u8; MAX_RECORD - record::HEADER_BYTES];
        assert!(sample_record(sample::READ, 0, &vals(), &fits).is_some());
    }
}
