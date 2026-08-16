//! One inode-number space across layers that each have their own.
//!
//! Two files on two layers can hold the same inode number, and an overlay that
//! reported both would make `find -samefile`, `du` and `tar --hard-dereference`
//! treat unrelated files as one. Remapping puts a layer tag in the high bits
//! that the layer itself does not use, so numbers stay unique without being
//! invented — which matters because an invented number changes whenever the
//! inode is evicted.

/// How the mount reports inode numbers, decided once the layers are known.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Layers are all one filesystem: their numbers are already unique.
    SameFs,
    /// High bits are free on every layer: tag them with the layer index.
    Bits(u32),
    /// No spare bits, so each layer keeps its own device number instead and
    /// only `st_dev` distinguishes them.
    Off,
}

impl Mode {
    /// Do every object's numbers come from one space? # C: O(1)
    pub fn same_dev(self) -> bool { !matches!(self, Mode::Off) }
    /// Are all layers one filesystem, needing no remap at all? # C: O(1)
    pub fn same_fs(self) -> bool { matches!(self, Mode::SameFs) }
    /// Bits available for the layer tag; zero when nothing is remapped. # C: O(1)
    pub fn bits(self) -> u32 { match self { Mode::Bits(b) => b, _ => 0 } }
}

/// Tag `ino` with `fsid`.
///
/// The lowest tag bit is reserved for the numbers the overlay invents for
/// objects that have none, so a real number is shifted one further up than the
/// tag width alone would need. A number too large to tag is returned as it
/// stands: a duplicate is a worse answer than a wrong-looking one, but an
/// inode number that changes under a running program is worse than both.
/// # C: O(1)
pub fn remap(ino: u64, bits: u32, fsid: u32) -> u64 {
    if bits == 0 || bits >= 64 { return ino; }
    let shift = 64 - bits;
    if ino >> shift != 0 { return ino; }
    ino | ((fsid as u64) << (shift + 1))
}

/// Would `ino` lose its tag? The mount warns on this once when `xino=on` asked
/// for remapping explicitly, and stays silent under `xino=auto`. # C: O(1)
pub fn overflows(ino: u64, bits: u32) -> bool {
    bits != 0 && bits < 64 && (ino >> (64 - bits)) != 0
}

/// Bits above the largest inode number a layer can produce, given the width
/// its handles encode. A layer whose numbers span the whole word leaves none,
/// and the mount falls back to separate device numbers. # C: O(1)
pub fn spare_bits(max_ino: u64) -> u32 { max_ino.leading_zeros() }

#[cfg(test)]
#[path = "xino/tests.rs"]
mod tests;
