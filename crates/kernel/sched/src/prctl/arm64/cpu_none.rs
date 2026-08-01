// Every non-aarch64 target: the `ID_AA64*_EL1` registers do not exist, so no
// feature is present and every arm64-only option answers EINVAL — which is
// what the generic `prctl` switch does on x86_64, where the per-arch macros
// are the `(-EINVAL)` defaults.

/// The optional CPU features the arm64 `prctl` options are gated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Features {
    pub sve: bool,
    pub sme: bool,
    pub mte: bool,
    pub address_auth: bool,
    pub generic_auth: bool,
}

/// # C: O(1)
pub fn features() -> Features { Features::default() }
