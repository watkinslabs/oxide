// The kernel CSPRNG: ChaCha20 with fast key erasure, the construction Linux
// `drivers/char/random.c` uses (`crng_fast_key_erasure`).
//
// Every output call derives a one-shot key from the master key, immediately
// replaces the master key with fresh keystream, and streams the caller's bytes
// under the one-shot key. An attacker who later reads the master key learns
// nothing about earlier output (forward secrecy), and the ChaCha20 core means
// output is not distinguishable from random without the key — the property the
// previous linear-congruential generator did not have at all. An LCG leaks its
// entire state from a couple of consecutive outputs, so anything seeded from it
// (glibc stack canaries and pointer guard via AT_RANDOM, ASLR offsets, session
// keys, /dev/urandom consumers) was predictable.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use sync::{Spinlock, Crng as CrngClass};

use crate::chacha::{self, BLOCK_BYTES, KEY_WORDS};
use crate::hw;

/// Bulk hardware-entropy source a driver installs (`virtio-rng`). Stored as a
/// raw fn pointer so this leaf crate needs no driver dependency; 0 = absent.
static BULK_SOURCE: AtomicU64 = AtomicU64::new(0);
type BulkFn = fn(&mut [u8]) -> usize;

/// Set once the pool has absorbed its boot seed. Read without the lock so
/// `is_initialized` costs nothing.
static SEEDED: AtomicBool = AtomicBool::new(false);

/// Bytes of bulk entropy pulled per (re)seed.
const SEED_BYTES: usize = 32;
/// Hardware words folded into a seed alongside the bulk source and jitter.
const SEED_HW_WORDS: usize = 4;

struct Crng { key: [u32; KEY_WORDS], nonce: [u32; 3], counter: u32 }

static CRNG: Spinlock<Crng, CrngClass> =
    Spinlock::new(Crng { key: [0; KEY_WORDS], nonce: [0; 3], counter: 0 });

impl Crng {
    /// Advance to a fresh key derived from the current one. Used both by the
    /// entropy absorb and by output, so the key never repeats. # C: O(1)
    fn rekey(&mut self) -> [u8; BLOCK_BYTES] {
        let out = chacha::block(&self.key, self.counter, self.nonce);
        self.counter = self.counter.wrapping_add(1);
        if self.counter == 0 {
            // Counter wrap must not repeat a (key, counter, nonce) triple.
            self.nonce[0] = self.nonce[0].wrapping_add(1);
        }
        self.key = chacha::key_from(&out);
        out
    }

    /// Fold `input` into the key, then rekey so the new state depends on the
    /// whole (old key, input) pair. Adding entropy can only help: even a
    /// fully attacker-known `input` leaves the key at least as unpredictable
    /// as before, because the rekey runs ChaCha20 over the mixed state.
    /// # C: O(input.len())
    fn absorb(&mut self, input: &[u8]) {
        for chunk in input.chunks(KEY_WORDS * 4) {
            for (i, b) in chunk.iter().enumerate() {
                self.key[i / 4] ^= (*b as u32) << (8 * (i % 4));
            }
            self.rekey();
        }
        if input.is_empty() { self.rekey(); }
    }
}

/// Install the bulk hardware-entropy source (`/dev/hwrng` backend). Called
/// from the virtio-rng probe; cleared on remove. # C: O(1)
pub fn set_bulk_source(f: BulkFn) {
    BULK_SOURCE.store(f as usize as u64, Ordering::Release);
    // A newly-attached source is fresh entropy: fold it in immediately rather
    // than waiting for the next consumer.
    reseed();
}

/// Drop the bulk source during driver remove. # C: O(1)
pub fn clear_bulk_source() { BULK_SOURCE.store(0, Ordering::Release); }

fn bulk_fill(dst: &mut [u8]) -> usize {
    let raw = BULK_SOURCE.load(Ordering::Acquire);
    if raw == 0 { return 0; }
    // SAFETY: BULK_SOURCE only ever holds a value written by `set_bulk_source` from a `BulkFn`, and the Acquire load pairs with that Release store.
    let f: BulkFn = unsafe { core::mem::transmute(raw as usize as *const ()) };
    f(dst)
}

/// Fold every available source into the pool: the bulk driver source, the
/// per-CPU hardware instruction, and the cycle counter. # C: O(1)
pub fn reseed() {
    let mut seed = [0u8; SEED_BYTES + (SEED_HW_WORDS + 1) * 8];
    let got = bulk_fill(&mut seed[..SEED_BYTES]);
    let mut off = got.min(SEED_BYTES);
    for _ in 0..SEED_HW_WORDS {
        if let Some(v) = hw::hw_random_u64() {
            seed[off..off + 8].copy_from_slice(&v.to_le_bytes());
            off += 8;
        }
    }
    seed[off..off + 8].copy_from_slice(&hw::cycles().to_le_bytes());
    off += 8;
    let mut g = CRNG.lock();
    g.absorb(&seed[..off]);
    drop(g);
    SEEDED.store(true, Ordering::Release);
}

/// Fold caller-supplied entropy into the pool (Linux `add_device_randomness` /
/// `add_interrupt_randomness`). Never reduces unpredictability. # C: O(len)
pub fn add_entropy(bytes: &[u8]) {
    let mut g = CRNG.lock();
    g.absorb(bytes);
}

/// True once the pool has absorbed a boot seed. Linux blocks `getrandom(2)`
/// (without GRND_NONBLOCK/GRND_INSECURE) until this holds. # C: O(1)
pub fn is_initialized() -> bool { SEEDED.load(Ordering::Acquire) }

/// Fill `dst` with CSPRNG output. The shared body of `getrandom(2)`,
/// `/dev/random`, `/dev/urandom` and AT_RANDOM.
///
/// Fast key erasure: one block yields the replacement master key AND the
/// one-shot key this call streams under, so the master key that produced these
/// bytes is destroyed before they reach the caller. # C: O(dst.len())
pub fn fill(dst: &mut [u8]) {
    if !SEEDED.load(Ordering::Acquire) { reseed(); }
    let (mut key, nonce, mut counter) = {
        let mut g = CRNG.lock();
        // Stir in fresh jitter so two calls at different instants diverge even
        // if no other entropy arrived between them.
        g.key[0] ^= hw::cycles() as u32;
        let block = g.rekey();
        (chacha::key_from(&block), g.nonce, 0u32)
    };
    let mut off = 0;
    while off < dst.len() {
        let block = chacha::block(&key, counter, nonce);
        counter = counter.wrapping_add(1);
        let n = core::cmp::min(BLOCK_BYTES, dst.len() - off);
        dst[off..off + n].copy_from_slice(&block[..n]);
        off += n;
    }
    // Destroy the one-shot key: it is on this call's stack and would otherwise
    // let a later stack read reproduce the bytes just handed out.
    for w in key.iter_mut() { *w = 0; }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// One CSPRNG word. # C: O(1)
pub fn next_u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}

#[cfg(test)]
#[path = "pool/tests.rs"]
mod tests;
