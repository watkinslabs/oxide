// The congestion-control registry `TCP_CONGESTION` resolves names through.
// Every algorithm the transport can actually run has an entry here and
// nowhere else, so a name that resolves is a name the sender will use.

/// The name buffer size the option copies in and out; names are NUL-padded to
/// it on read and NUL-terminated within it on write.
pub const CA_NAME_MAX: usize = 16;

/// One registered congestion control. The discriminant is the value stored in
/// the socket's option state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CongestionAlgo { Reno = 0, Cubic = 1 }

/// The algorithm a socket starts on.
pub const DEFAULT: CongestionAlgo = CongestionAlgo::Cubic;

/// A registry entry: the wire name plus whether an unprivileged caller may
/// switch to it. Only an algorithm marked unrestricted is selectable without
/// `CAP_NET_ADMIN`.
struct Entry { name: &'static str, algo: CongestionAlgo, unrestricted: bool }

const REGISTRY: &[Entry] = &[
    Entry { name: "reno",  algo: CongestionAlgo::Reno,  unrestricted: true },
    Entry { name: "cubic", algo: CongestionAlgo::Cubic, unrestricted: false },
];

impl CongestionAlgo {
    /// # C: O(1)
    pub const fn as_u8(self) -> u8 { self as u8 }

    /// Recover an algorithm from its stored slot; an unknown slot falls back
    /// to the default rather than inventing a sender behaviour. # C: O(1)
    pub const fn from_u8(raw: u8) -> Self {
        match raw { 0 => Self::Reno, 1 => Self::Cubic, _ => DEFAULT }
    }

    /// The registered name. # C: O(1)
    pub fn name(self) -> &'static str {
        match self { Self::Reno => "reno", Self::Cubic => "cubic" }
    }

    /// Whether an unprivileged caller may switch to it. # C: O(1)
    pub fn unrestricted(self) -> bool {
        REGISTRY.iter().find(|e| e.algo == self).is_some_and(|e| e.unrestricted)
    }
}

/// Resolve a registered name. # C: O(registry)
pub fn find(name: &str) -> Option<CongestionAlgo> {
    REGISTRY.iter().find(|e| e.name == name).map(|e| e.algo)
}

/// The NUL-padded name buffer the read direction publishes. # C: O(1)
pub fn name_buf(algo: CongestionAlgo) -> [u8; CA_NAME_MAX] {
    let mut out = [0u8; CA_NAME_MAX];
    let bytes = algo.name().as_bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registry_name_resolves_to_its_own_entry() {
        for entry in REGISTRY {
            assert_eq!(find(entry.name), Some(entry.algo));
            assert_eq!(entry.algo.name(), entry.name);
        }
    }

    #[test]
    fn unknown_name_does_not_resolve() {
        assert_eq!(find("bbr"), None);
        assert_eq!(find(""), None);
        assert_eq!(find("cubi"), None);
    }

    #[test]
    fn slot_round_trips_and_unknown_slot_is_the_default() {
        for entry in REGISTRY {
            assert_eq!(CongestionAlgo::from_u8(entry.algo.as_u8()), entry.algo);
        }
        assert_eq!(CongestionAlgo::from_u8(200), DEFAULT);
    }

    #[test]
    fn reno_is_unrestricted_and_cubic_is_not() {
        // The restriction bit is what decides whether switching needs
        // CAP_NET_ADMIN; only the algorithm that carries it is free.
        assert!(CongestionAlgo::Reno.unrestricted());
        assert!(!CongestionAlgo::Cubic.unrestricted());
    }

    #[test]
    fn published_name_is_nul_padded_to_the_full_buffer() {
        let buf = name_buf(CongestionAlgo::Reno);
        assert_eq!(&buf[..4], b"reno");
        assert!(buf[4..].iter().all(|b| *b == 0));
    }
}
