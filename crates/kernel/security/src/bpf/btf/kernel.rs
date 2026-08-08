// The kernel's own BTF: type information this kernel publishes about
// itself, and the attach-target resolution that reads it.
//
// A program names its attach target by a type id in this object, exactly
// as it names one in a loaded object. The blob is built from the published
// LSM hook table so the two can never disagree, and it is handed to the
// same parser that validates a user-supplied object — an object this
// kernel would refuse from userspace is an object it must not publish.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};

use crate::bpf_lsm::{Hook, hook_by_stub_name, HOOKS};
use super::super::iter::{IterTarget, target_by_stub_name};
use super::super::iter::targets::TARGETS as ITER_TARGETS;
use super::format::{FLAGS_NONE, HEADER_LEN, Kind, MAGIC, VERSION};
use super::parse::{BtfIndex, parse};

/// Byte width of the `int` type the hook stubs return.
const INT_BYTES: u32 = 4;
/// `BTF_INT_SIGNED`.
const INT_SIGNED: u32 = 1;
/// Encoding/offset/bits packing of a `BTF_KIND_INT` payload word.
const INT_ENCODING_SHIFT: u32 = 24;
/// Bit width of the `int` type.
const INT_BITS: u32 = INT_BYTES * 8;
/// `BTF_FUNC_GLOBAL` linkage, carried in a `BTF_KIND_FUNC` vlen.
const FUNC_GLOBAL: u32 = 1;
/// Kind field position inside a type record's `info` word.
const INFO_KIND_SHIFT: u32 = 24;
/// Type id of the `int` record every hook stub returns. First record.
const INT_TYPE_ID: u32 = 1;

struct Builder {
    strings: Vec<u8>,
    types: Vec<u8>,
    next_id: u32,
}

impl Builder {
    fn new() -> Self {
        // Offset 0 of the string section is the empty name.
        Self { strings: alloc::vec![0u8], types: Vec::new(), next_id: 1 }
    }

    fn name(&mut self, text: &str) -> u32 {
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(text.as_bytes());
        self.strings.push(0);
        off
    }

    fn record(&mut self, name_off: u32, kind: Kind, vlen: u32, size_or_type: u32,
        payload: &[u32]) -> u32
    {
        let info = (kind as u32) << INFO_KIND_SHIFT | vlen;
        for word in [name_off, info, size_or_type] {
            self.types.extend_from_slice(&word.to_ne_bytes());
        }
        for word in payload { self.types.extend_from_slice(&word.to_ne_bytes()); }
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

/// One stub function this kernel declares as an attachable target.
struct Stub {
    name: &'static str,
    args: &'static [&'static str],
}

/// Every stub the object declares, hooks first and then iterator targets.
/// Both attach-target families are named the same way, so they are
/// published from one walk rather than from two objects that could
/// disagree about a type id.
/// # C: O(hooks + iterator targets)
fn published_stubs() -> Vec<Stub> {
    let mut stubs = Vec::new();
    for (_, spec) in HOOKS { stubs.push(Stub { name: spec.stub, args: spec.args }); }
    for (_, spec) in ITER_TARGETS { stubs.push(Stub { name: spec.stub, args: spec.args }); }
    stubs
}

/// Build the raw object. Declares one `int`, then per stub: an opaque
/// forward declaration per argument type, a pointer to each, the stub's
/// prototype, and the stub function itself.
/// # C: O(total stub argument count)
fn build() -> Vec<u8> {
    let mut b = Builder::new();
    let int_name = b.name("int");
    let int_payload = INT_SIGNED << INT_ENCODING_SHIFT | INT_BITS;
    b.record(int_name, Kind::Int, 0, INT_BYTES, &[int_payload]);
    for stub in published_stubs() {
        let mut params = Vec::new();
        for arg in stub.args {
            let arg_name = b.name(arg);
            let fwd = b.record(arg_name, Kind::Fwd, 0, 0, &[]);
            let ptr = b.record(0, Kind::Ptr, 0, fwd, &[]);
            params.push((arg_name, ptr));
        }
        let mut payload = Vec::new();
        for (arg_name, ptr) in &params { payload.push(*arg_name); payload.push(*ptr); }
        let proto = b.record(0, Kind::FuncProto, params.len() as u32, INT_TYPE_ID, &payload);
        let stub_name = b.name(stub.name);
        b.record(stub_name, Kind::Func, FUNC_GLOBAL, proto, &[]);
    }
    let type_len = b.types.len() as u32;
    let str_len = b.strings.len() as u32;
    let mut raw = Vec::new();
    raw.extend_from_slice(&MAGIC.to_ne_bytes());
    raw.push(VERSION);
    raw.push(FLAGS_NONE);
    for word in [HEADER_LEN as u32, 0, type_len, type_len, str_len, 0, 0] {
        raw.extend_from_slice(&word.to_ne_bytes());
    }
    raw.extend_from_slice(&b.types);
    raw.extend_from_slice(&b.strings);
    raw
}

/// The published object: its exact bytes plus the parser's type index.
pub(super) struct KernelBtf {
    raw: Vec<u8>,
    index: BtfIndex,
}

static PUBLISHED: Spinlock<Option<Arc<KernelBtf>>, TaskListClass> = Spinlock::new(None);

/// Pin the published object, building it on first use. `None` when the
/// object this kernel would publish does not survive its own parser, which
/// makes every attach target unresolvable rather than resolvable against
/// something unvalidated.
/// # C: O(1) after first call
/// # Ctx: process; caller holds no `TaskListClass` lock
/// # Lk: takes `TaskListClass`
/// # Sleeps: no
pub(super) fn published() -> Option<Arc<KernelBtf>> {
    let mut slot = PUBLISHED.lock();
    if let Some(btf) = slot.as_ref() { return Some(Arc::clone(btf)); }
    let raw = build();
    let index = parse(&raw).ok()?;
    let btf = Arc::try_new(KernelBtf { raw, index }).ok()?;
    *slot = Some(Arc::clone(&btf));
    Some(btf)
}

impl KernelBtf {
    /// Exact bytes this kernel publishes. One copy, shared by every reader:
    /// the attach-target resolver below parses these same bytes, so a loader
    /// that reads them can never be told a type id the load path would then
    /// refuse to resolve. # C: O(1)
    pub(crate) fn raw(&self) -> &[u8] { &self.raw }
}

/// Byte length of the published object; 0 when this kernel publishes none.
/// # C: O(1) after first call
pub(crate) fn published_len() -> u64 {
    published().map(|btf| btf.raw().len() as u64).unwrap_or(0)
}

/// Windowed copy of the published object into `buf` starting at `off`,
/// returning the byte count copied — 0 once `off` reaches the end. The read
/// half of the binary attribute a loader opens to discover the type ids it
/// names as attach targets. # C: O(n)
pub(crate) fn published_read(off: u64, buf: &mut [u8]) -> usize {
    let Some(btf) = published() else { return 0 };
    let raw = btf.raw();
    let Ok(off) = usize::try_from(off) else { return 0 };
    if off >= raw.len() { return 0; }
    let n = (raw.len() - off).min(buf.len());
    buf[..n].copy_from_slice(&raw[off..off + n]);
    n
}

/// Resolve one attach target id against the kernel's own type information.
/// A target that is not a function, or is a function that is not one of the
/// published LSM hook stubs, resolves to nothing.
/// # C: O(hook count)
pub(crate) fn lsm_hook_by_btf_id(btf_id: u32) -> Option<Hook> {
    stub_name_by_btf_id(btf_id).and_then(|name| hook_by_stub_name(&name))
}

/// Resolve one attach target id to the iterator target its stub names.
/// # C: O(target count)
pub(crate) fn iter_target_by_btf_id(btf_id: u32) -> Option<IterTarget> {
    stub_name_by_btf_id(btf_id).and_then(|name| target_by_stub_name(&name))
}

/// Name of the stub function one type id declares, when it declares one.
/// # C: O(1)
fn stub_name_by_btf_id(btf_id: u32) -> Option<Vec<u8>> {
    let btf = published()?;
    btf.index.func_name(&btf.raw, btf_id).map(|name| name.to_vec())
}

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod tests;
