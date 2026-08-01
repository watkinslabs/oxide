// The upper-layer-protocol registry `TCP_ULP` resolves names through. A ULP
// interposes on the socket's send and receive path, so only a protocol this
// transport can actually run may be registered; the registry is the single
// place that decides, and an unregistered name is not attachable.

/// The name buffer size the option copies in and out.
pub const ULP_NAME_MAX: usize = 16;

/// One registered upper-layer protocol. No transport in this kernel
/// interposes on the TCP data path, so the registry is empty and every name
/// fails to resolve — the answer a kernel built without any ULP gives.
struct Entry { name: &'static str, id: u8 }

const REGISTRY: &[Entry] = &[];

/// Resolve a registered ULP name. # C: O(registry)
pub fn find(name: &str) -> Option<u8> {
    REGISTRY.iter().find(|e| e.name == name).map(|e| e.id)
}

/// The name of an attached ULP by slot. # C: O(registry)
pub fn name(id: u8) -> Option<&'static str> {
    REGISTRY.iter().find(|e| e.id == id).map(|e| e.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_name_resolves_while_the_registry_is_empty() {
        // Attaching a ULP has to change what the send/receive path does; with
        // nothing registered the lookup must fail rather than record a name
        // that no data path honours.
        assert_eq!(find("tls"), None);
        assert_eq!(find("espintcp"), None);
        assert_eq!(find(""), None);
        assert_eq!(name(0), None);
    }

    #[test]
    fn every_registered_name_round_trips() {
        for entry in REGISTRY {
            assert_eq!(find(entry.name), Some(entry.id));
            assert_eq!(name(entry.id), Some(entry.name));
        }
    }
}
