// Inline encryption for the block layer — what Linux calls blk-crypto.
//
// A request may carry an ENCRYPTION CONTEXT: a key and the data unit number
// its first data unit is encrypted under. Storage that can do the crypto
// itself advertises a PROFILE saying which modes, data unit sizes, data-unit-
// number widths and key types it accepts; a request whose context the device
// can serve is handed down untouched and the device en/decrypts it in line
// with the transfer.
//
// When no device can serve the context, the FALLBACK does the same crypto in
// software before the write leaves and after the read arrives. That path is
// not an optimisation and not optional: a mount that asked for inline crypto
// and quietly got plaintext on the medium is the one outcome this whole module
// exists to make impossible. Every path here either encrypts or refuses.
//
// Module manifest:
// - `mode`     — the modes a key may name and the widths each one fixes.
// - `dun`      — the data unit number: a multi-limb counter and its IV bytes.
// - `key`      — a key's configuration, its bytes, and what makes one valid.
// - `ctx`      — a request's encryption context, and when two may share one
//                request.
// - `cipher`   — the software construction each mode names.
// - `profile`  — what a device advertises, its keyslots, and the driver calls
//                that program and evict keys.
// - `fallback` — the software profile that serves a context no device can.
// - `submit`   — the choke point every submitter with a context goes through.

pub mod mode;
pub mod dun;
pub mod key;
pub mod ctx;
pub mod cipher;
pub mod profile;
pub mod fallback;
pub mod submit;

pub use mode::{Mode, ModeParams, MODE_SLOTS};
pub use dun::{Dun, DUN_LIMBS, MAX_IV_SIZE};
pub use key::{Config, Key, KeyType, KeyTypes, MAX_HW_WRAPPED_KEY_SIZE, MAX_RAW_KEY_SIZE, SW_SECRET_SIZE};
pub use ctx::Ctx;
pub use profile::{LlOps, Profile, SlotRef};
pub use submit::{config_supported, config_supported_natively, derive_sw_secret,
                 evict_key, profile_supports, start_using_key, start_using_key_on,
                 submit_sync};

#[cfg(test)]
mod tests;
