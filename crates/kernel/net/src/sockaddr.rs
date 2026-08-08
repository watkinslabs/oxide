//! Copied `sockaddr_storage` parsing and policy rewrite fields.

use alloc::vec::Vec;

pub const SOCKADDR_STORAGE_LEN: usize = 128;
/// `sizeof(struct sockaddr_un)` — two family bytes plus a 108-byte path.
pub const SOCKADDR_UN_LEN: usize = 110;
/// `offsetof(struct sockaddr_un, sun_path)`.
pub const SOCKADDR_UN_PATH_OFFSET: usize = 2;

/// `unix_validate_addr`: the caller length must reach past `sun_family` and
/// must not exceed `struct sockaddr_un`, and the family must be AF_UNIX.
/// # C: O(1)
pub fn validate_unix_addr(family: u16, addrlen: usize) -> Result<(), syscall::errno::Errno> {
    if addrlen <= SOCKADDR_UN_PATH_OFFSET || addrlen > SOCKADDR_UN_LEN {
        return Err(syscall::errno::Errno::Einval);
    }
    if family != crate::socket_args::AF_UNIX as u16 { return Err(syscall::errno::Errno::Einval); }
    Ok(())
}

pub struct SockaddrStorage {
    bytes: [u8; SOCKADDR_STORAGE_LEN],
    len: usize,
}

impl SockaddrStorage {
    /// Retain one already-copied userspace sockaddr. # C: O(len)
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() > SOCKADDR_STORAGE_LEN { return None; }
        let mut bytes = [0u8; SOCKADDR_STORAGE_LEN];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Self { bytes, len: raw.len() })
    }

    /// Caller-declared copied length. # C: O(1)
    pub fn len(&self) -> usize { self.len }

    /// Whether the copied address is empty. # C: O(1)
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Exact caller-declared bytes retained by the single copy-in. # C: O(1)
    pub fn as_bytes(&self) -> &[u8] { &self.bytes[..self.len] }

    /// Native-endian `sa_family`. # C: O(1)
    pub fn family(&self) -> Option<u16> {
        (self.len >= 2).then(|| u16::from_ne_bytes([self.bytes[0], self.bytes[1]]))
    }

    /// Linux pathname/abstract `sockaddr_un` bytes. # C: O(108)
    pub fn unix_path(&self) -> Option<Vec<u8>> {
        if self.len <= 2 { return None; }
        let path = &self.bytes[2..self.len.min(110)];
        if path.first() == Some(&0) { return Some(path.to_vec()); }
        Some(path.iter().copied().take_while(|byte| *byte != 0).collect())
    }

    /// IPv4 address plus host-order port. # C: O(1)
    pub fn inet4(&self) -> Option<(crate::Ipv4Addr, u16)> {
        if self.len < 8 { return None; }
        Some((
            crate::Ipv4Addr::new(self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]),
            u16::from_be_bytes([self.bytes[2], self.bytes[3]]),
        ))
    }

    /// IPv6 address, host-order port, and optional scope. # C: O(1)
    pub fn inet6(&self) -> Option<(crate::Ipv6Addr, u16, u32)> {
        if self.len < 24 { return None; }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.bytes[8..24]);
        let scope = if self.len >= 28 {
            u32::from_ne_bytes(self.bytes[24..28].try_into().ok()?)
        } else { 0 };
        Some((crate::Ipv6Addr(addr),
            u16::from_be_bytes([self.bytes[2], self.bytes[3]]), scope))
    }

    /// `sin6_flowinfo`, in host order. The field sits between the port and
    /// the address, so every `sockaddr_in6` long enough to carry an address
    /// carries it too — its meaning, not its presence, is what
    /// `IPV6_FLOWINFO_SEND` decides (`sock_opts::sol_ipv6::sndflow`).
    /// # C: O(1)
    pub fn inet6_flowinfo(&self) -> Option<u32> {
        if self.len < 24 { return None; }
        Some(u32::from_be_bytes(self.bytes[4..8].try_into().ok()?))
    }

    /// Raw network-order IPv4 fields for `bpf_sock_addr`. # C: O(1)
    pub fn bpf_fields_v4(&self) -> Option<(u32, [u32; 4], u32)> {
        let port = u16::from_ne_bytes([*self.bytes.get(2)?, *self.bytes.get(3)?]) as u32;
        let ip4 = u32::from_ne_bytes(self.bytes.get(4..8)?.try_into().ok()?);
        Some((ip4, [0; 4], port))
    }

    /// Raw network-order IPv6 fields for `bpf_sock_addr`. # C: O(1)
    pub fn bpf_fields_v6(&self) -> Option<(u32, [u32; 4], u32)> {
        if self.len < 24 { return None; }
        let port = u16::from_ne_bytes([self.bytes[2], self.bytes[3]]) as u32;
        let mut ip6 = [0u32; 4];
        for (index, word) in ip6.iter_mut().enumerate() {
            let start = 8 + index * 4;
            *word = u32::from_ne_bytes(self.bytes[start..start + 4].try_into().ok()?);
        }
        Some((0, ip6, port))
    }

    /// Publish successful IPv4 BPF address and port rewrites. # C: O(1)
    pub fn apply_bpf_fields_v4(&mut self, ip4: u32, port: u32) {
        if self.len >= 4 { self.bytes[2..4].copy_from_slice(&(port as u16).to_ne_bytes()); }
        if self.len >= 8 { self.bytes[4..8].copy_from_slice(&ip4.to_ne_bytes()); }
    }

    /// Publish successful IPv6 BPF address and port rewrites. # C: O(1)
    pub fn apply_bpf_fields_v6(&mut self, ip6: [u32; 4], port: u32) {
        if self.len >= 4 { self.bytes[2..4].copy_from_slice(&(port as u16).to_ne_bytes()); }
        if self.len >= 24 {
            for (index, word) in ip6.iter().enumerate() {
                let start = 8 + index * 4;
                self.bytes[start..start + 4].copy_from_slice(&word.to_ne_bytes());
            }
        }
    }

    /// Native AF_VSOCK tuple. # C: O(1)
    pub fn vsock(&self) -> Option<(u16, u32, u64)> {
        if self.len < 16 { return None; }
        Some((self.family()?,
            u32::from_ne_bytes(self.bytes[4..8].try_into().ok()?),
            u32::from_ne_bytes(self.bytes[8..12].try_into().ok()?) as u64))
    }

    /// AF_PACKET protocol and signed interface index. # C: O(1)
    pub fn packet(&self) -> Option<(u16, i32)> {
        if self.len < 8 { return None; }
        Some((
            u16::from_ne_bytes(self.bytes[2..4].try_into().ok()?),
            i32::from_ne_bytes(self.bytes[4..8].try_into().ok()?),
        ))
    }
}

#[cfg(test)]
mod tests {
    // `unix_validate_addr` bounds: an address that only covers `sun_family`
    // carries no name, and one longer than `struct sockaddr_un` is rejected
    // outright rather than truncated to the embedded path.
    #[test]
    fn unix_addresses_are_bounded_by_the_sockaddr_un_shape() {
        use syscall::errno::Errno;
        let unix = super::super::socket_args::AF_UNIX as u16;
        assert_eq!(super::validate_unix_addr(unix, 0), Err(Errno::Einval));
        assert_eq!(super::validate_unix_addr(unix, 2), Err(Errno::Einval));
        assert_eq!(super::validate_unix_addr(unix, 3), Ok(()));
        assert_eq!(super::validate_unix_addr(unix, super::SOCKADDR_UN_LEN), Ok(()));
        assert_eq!(super::validate_unix_addr(unix, super::SOCKADDR_UN_LEN + 1), Err(Errno::Einval));
        // The length screen outranks the family comparison.
        assert_eq!(super::validate_unix_addr(0, 128), Err(Errno::Einval));
        assert_eq!(super::validate_unix_addr(0, 8), Err(Errno::Einval));
    }

    use super::SockaddrStorage;

    #[test]
    fn ipv4_policy_rewrite_updates_normal_parser() {
        let mut raw = [0u8; 16];
        raw[..2].copy_from_slice(&2u16.to_ne_bytes());
        raw[2..4].copy_from_slice(&53u16.to_be_bytes());
        raw[4..8].copy_from_slice(&[192, 0, 2, 1]);
        let mut storage = SockaddrStorage::from_bytes(&raw).unwrap();
        let (_, ip6, _) = storage.bpf_fields_v4().unwrap();
        assert_eq!(ip6, [0; 4]);
        storage.apply_bpf_fields_v4(
            u32::from_ne_bytes([198, 51, 100, 2]), u16::from_be(5353) as u32);
        assert_eq!(storage.inet4(), Some((crate::Ipv4Addr::new(198, 51, 100, 2), 5353)));
    }

    #[test]
    fn ipv6_policy_rewrite_preserves_scope() {
        let mut raw = [0u8; 28];
        raw[..2].copy_from_slice(&10u16.to_ne_bytes());
        raw[2..4].copy_from_slice(&443u16.to_be_bytes());
        raw[24..28].copy_from_slice(&7u32.to_ne_bytes());
        let mut storage = SockaddrStorage::from_bytes(&raw).unwrap();
        let (ip4, _, _) = storage.bpf_fields_v6().unwrap();
        assert_eq!(ip4, 0);
        let words = [
            u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8]),
            0, 0, u32::from_ne_bytes([0, 0, 0, 1]),
        ];
        storage.apply_bpf_fields_v6(words, u16::from_be(8443) as u32);
        let (ip, port, scope) = storage.inet6().unwrap();
        assert_eq!(ip, crate::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]));
        assert_eq!((port, scope), (8443, 7));
    }
}
