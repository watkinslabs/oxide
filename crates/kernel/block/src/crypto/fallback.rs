//! The software profile that serves an encryption context no device can.
//!
//! Its existence is what makes inline encryption a property of the FILESYSTEM
//! rather than of the hardware it happens to be on. Without it, a mount asking
//! for inline crypto on a device with no inline crypto has two options — write
//! the data in the clear or fail every write — and the first is silent. With
//! it there is a third, which is to do in software precisely what the device
//! would have done, so the bytes on the medium are the same either way and a
//! disk carried to a machine with the hardware still reads.
//!
//! It is modelled as a PROFILE, with keyslots, rather than as a special case
//! in the submission path. That is not decoration: it means the keyslot
//! machinery, the capability check and the eviction path are the same code the
//! hardware path uses and are exercised on every machine, instead of the
//! hardware path being the only one that runs them and being untested.
//!
//! What it will NOT serve is a hardware-wrapped key. Such a key is not key
//! material — no software can encrypt with it — so the profile advertises raw
//! keys only and a wrapped key is refused here rather than being served by
//! something that is not the key.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU32, Ordering};

use sync::{LockClass, Spinlock};

use crate::crypto::cipher::Cipher;
use crate::crypto::ctx::Ctx;
use crate::crypto::key::{Key, KeyTypes};
use crate::crypto::mode::{Mode, MODE_SLOTS};
use crate::crypto::profile::{LlOps, Profile};
use crate::types::{BlockError, KResult};

/// The prepared constructions behind the fallback's keyslots.
///
/// A separate class from the profile's own table and ranked directly above it:
/// programming a slot is a driver call the profile makes with its table held,
/// so this is always the inner of the two and never the outer.
pub struct FallbackSlots;
impl LockClass for FallbackSlots {
    fn rank() -> u16 { 138 }
    fn name() -> &'static str { "BlkCryptoFallbackSlots" }
}

/// The fallback's one-time construction.
pub struct FallbackInit;
impl LockClass for FallbackInit {
    fn rank() -> u16 { 136 }
    fn name() -> &'static str { "BlkCryptoFallbackInit" }
}

/// Keyslots the fallback offers.
///
/// A slot costs a prepared construction and nothing else, so the count exists
/// to bound memory rather than to model scarce hardware — but it is finite on
/// purpose: a fallback with unlimited slots would never exercise the
/// least-recently-used replacement the hardware path depends on.
pub const FALLBACK_KEYSLOTS: usize = 64;

/// The constructions the fallback's slots hold.
struct Slots(Spinlock<Vec<Option<Cipher>>, FallbackSlots>);

impl LlOps for Slots {
    /// # C: O(1)
    fn keyslot_program(&self, key: &Key, slot: usize) -> KResult<()> {
        let c = Cipher::prepare(key.config().mode, key.bytes())?;
        self.0.lock()[slot] = Some(c);
        Ok(())
    }

    /// # C: O(1)
    fn keyslot_evict(&self, _key: &Key, slot: Option<usize>) -> KResult<()> {
        if let Some(i) = slot { self.0.lock()[i] = None; }
        Ok(())
    }
}

struct Fallback {
    profile: Arc<Profile>,
    slots: Arc<Slots>,
}

static FALLBACK: Spinlock<Option<Fallback>, FallbackInit> = Spinlock::new(None);

/// Modes a caller has declared it is about to use, one bit per mode index.
///
/// A request whose mode was never declared is refused rather than served. The
/// declaration is where a caller finds out whether this build can encrypt for
/// that mode at all, and it happens away from the I/O path on purpose; letting
/// an undeclared mode through would move that discovery into the middle of a
/// write, where the only remaining answers are wrong bytes or a lost write.
static STARTED: AtomicU32 = AtomicU32::new(0);

/// Build the fallback profile: every mode, every data unit size, the widest
/// data unit number, raw keys only. # C: O(FALLBACK_KEYSLOTS)
fn build() -> Fallback {
    let slots = Arc::new(Slots(Spinlock::new(
        (0..FALLBACK_KEYSLOTS).map(|_| None).collect::<Vec<_>>())));
    let mut p = Profile::new(slots.clone() as Arc<dyn LlOps>, FALLBACK_KEYSLOTS)
        .with_max_dun_bytes(crate::crypto::dun::MAX_IV_SIZE as u32)
        .with_key_types(KeyTypes::RAW);
    for m in Mode::ALL { p = p.with_mode(m, u32::MAX); }
    Fallback { profile: Arc::new(p), slots }
}

/// The fallback profile, constructed on first use. # C: amortised O(1)
fn profile() -> Arc<Profile> {
    let mut g = FALLBACK.lock();
    if g.is_none() { *g = Some(build()); }
    g.as_ref().map(|f| Arc::clone(&f.profile)).expect("just constructed")
}

/// The fallback's slot contents. # C: amortised O(1)
fn slots() -> Arc<Slots> {
    let mut g = FALLBACK.lock();
    if g.is_none() { *g = Some(build()); }
    g.as_ref().map(|f| Arc::clone(&f.slots)).expect("just constructed")
}

/// Declare that `mode` is about to be used, and learn whether this build can.
///
/// Every mode inline encryption defines has a software construction here, so
/// this refuses nothing today — but it is the place a mode without one would
/// be refused, and it must be called before any request using that mode, which
/// is what makes the refusal reach the caller instead of the write.
/// # C: O(1)
pub fn start_using_mode(mode: Mode) -> KResult<()> {
    // Constructing the profile here rather than at first I/O keeps allocation
    // off the submission path, which is the same reason the hardware path
    // programs keyslots outside it.
    let _ = profile();
    STARTED.fetch_or(1 << mode.index(), Ordering::Release);
    Ok(())
}

/// Whether `mode` was declared. # C: O(1)
fn started(mode: Mode) -> bool {
    STARTED.load(Ordering::Acquire) & (1 << mode.index()) != 0
}

/// Whether the fallback can serve `ctx`'s key at all. # C: O(1)
pub fn supports(key: &Key) -> bool { profile().supports(key.config()) }

/// Take `key` out of the fallback's slots. # C: O(FALLBACK_KEYSLOTS)
pub fn evict_key(key: &Arc<Key>) -> KResult<()> { profile().evict_key(key) }

/// Encrypt `buf` in place as the data units `ctx` names. # C: O(len(buf))
pub fn encrypt(ctx: &Ctx, buf: &mut [u8]) -> KResult<()> { crypt(ctx, buf, true) }

/// Decrypt `buf` in place as the data units `ctx` names. # C: O(len(buf))
pub fn decrypt(ctx: &Ctx, buf: &mut [u8]) -> KResult<()> { crypt(ctx, buf, false) }

/// One direction of the same walk: each data unit under its own number,
/// advancing by one unit at a time.
///
/// Refusing an unaligned length rather than encrypting a short final unit is
/// the only safe answer. A partial unit encrypted as if it were whole produces
/// bytes no reader can recover, and one padded out silently lengthens the
/// data.
/// # C: O(len(buf))
fn crypt(ctx: &Ctx, buf: &mut [u8], encrypting: bool) -> KResult<()> {
    let key = ctx.key();
    let cfg = key.config();
    if !started(cfg.mode) { return Err(BlockError::Eio); }
    // A wrapped key lands here, and this is where it stops: the fallback
    // advertises raw keys only, so `supports` is false and the request is
    // refused rather than served with something that is not the key.
    let p = profile();
    if !p.supports(cfg) { return Err(BlockError::Eopnotsupp); }
    let du = cfg.data_unit_size as usize;
    if buf.is_empty() || buf.len() % du != 0 { return Err(BlockError::Einval); }

    let slot = p.get_keyslot(key)?.ok_or(BlockError::Eio)?;
    let table = slots();
    let g = table.0.lock();
    let cipher = g[slot.index()].as_ref().ok_or(BlockError::Eio)?;
    let mut dun = ctx.dun();
    for unit in buf.chunks_exact_mut(du) {
        let iv = dun.to_iv();
        if encrypting { cipher.encrypt(&iv, unit)?; } else { cipher.decrypt(&iv, unit)?; }
        dun.increment(1);
    }
    Ok(())
}

/// Forget every declared mode and every prepared construction.
///
/// Exists for tests, which must be able to observe the refusal an undeclared
/// mode produces after another test has declared it — a global that only ever
/// gains state makes that check unable to fail.
/// # C: O(FALLBACK_KEYSLOTS)
#[cfg(any(test, feature = "hosted"))]
pub fn reset_for_test() {
    STARTED.store(0, Ordering::Release);
    *FALLBACK.lock() = None;
}

/// Every mode index fits the declaration word. # C: O(1)
const _: () = assert!(MODE_SLOTS <= 32);
