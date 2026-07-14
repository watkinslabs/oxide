use crate::netdev::{NetError, NetResult};

const ICMP6_FILTER_WORDS: usize = 8;

/// Linux `struct icmp6_filter`; set bits reject their ICMPv6 type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Icmp6Filter { words: [u32; ICMP6_FILTER_WORDS] }

impl Icmp6Filter {
    pub const PASS_ALL: Self = Self { words: [0; ICMP6_FILTER_WORDS] };
    pub const BLOCK_ALL: Self = Self { words: [u32::MAX; ICMP6_FILTER_WORDS] };

    /// Import the eight Linux ICMP6_FILTER words. # C: O(1)
    pub const fn from_words(words: [u32; ICMP6_FILTER_WORDS]) -> Self { Self { words } }

    /// Export the eight Linux ICMP6_FILTER words. # C: O(1)
    pub const fn words(self) -> [u32; ICMP6_FILTER_WORDS] { self.words }

    /// Test whether one ICMPv6 type survives this filter. # C: O(1)
    pub const fn accepts(self, typ: u8) -> bool {
        let word = (typ >> 5) as usize;
        let bit = typ & 31;
        self.words[word] & (1u32 << bit) == 0
    }
}

impl Default for Icmp6Filter { fn default() -> Self { Self::PASS_ALL } }

/// Linux `IPV6_CHECKSUM` state for one raw IPv6 socket.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Raw6Checksum { Disabled, Offset(u32) }

impl Raw6Checksum {
    /// Linux default: ICMPv6 checksum field at byte two; other protocols off. # C: O(1)
    pub const fn for_protocol(protocol: u8) -> Self {
        if protocol == crate::icmpv6::IPPROTO_ICMPV6 { Self::Offset(2) } else { Self::Disabled }
    }

    /// Validate one signed `IPV6_CHECKSUM` value. # C: O(1)
    pub fn from_linux(value: i32) -> NetResult<Self> {
        if value < 0 { return Ok(Self::Disabled); }
        if value & 1 != 0 { return Err(NetError::Einval); }
        Ok(Self::Offset(value as u32))
    }

    /// Export the Linux signed option value. # C: O(1)
    pub const fn linux_value(self) -> i32 {
        match self { Self::Disabled => -1, Self::Offset(offset) => offset as i32 }
    }
}
