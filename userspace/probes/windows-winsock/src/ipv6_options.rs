//! Winsock `IPV6_V6ONLY` state transition over the native IPv6 socket owner.

use crate::{WsaError, AF_INET, AF_INET6};

/// Winsock option number for the IPv6-only socket policy.
pub const IPV6_V6ONLY: u32 = 26;

/// Validation failures specific to the option's caller-visible lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6OnlyOptionError { WrongFamily, InvalidLength, NullValue, Bound }

impl Ipv6OnlyOptionError {
    /// Convert the option failure to the Winsock error vocabulary. # C: O(1)
    pub const fn wsa(self) -> WsaError {
        match self {
            Self::WrongFamily => WsaError::ProtocolFamilyNotSupported,
            Self::InvalidLength | Self::Bound => WsaError::InvalidArgument,
            Self::NullValue => WsaError::Fault,
        }
    }
}

/// One socket's option state; bind is the terminal point for changing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6OnlyOptions { family: u16, value: bool, bound: bool }

impl Ipv6OnlyOptions {
    /// Create the Windows default: IPv6 sockets start IPv6-only. # C: O(1)
    pub const fn new(family: u16) -> Result<Self, Ipv6OnlyOptionError> {
        match family {
            AF_INET | AF_INET6 => Ok(Self { family, value: true, bound: false }),
            _ => Err(Ipv6OnlyOptionError::WrongFamily),
        }
    }

    /// Read the option using the one-byte Winsock result width. # C: O(1)
    pub const fn get(&self, optlen: usize, optval_present: bool)
        -> Result<(bool, usize), Ipv6OnlyOptionError>
    {
        if optlen == 0 { return Err(Ipv6OnlyOptionError::InvalidLength); }
        if !optval_present { return Err(Ipv6OnlyOptionError::NullValue); }
        Ok((self.value, 1))
    }

    /// Set the option before bind; native socket ownership remains elsewhere. # C: O(1)
    pub const fn set(&mut self, value: bool, optlen: usize, optval_present: bool)
        -> Result<(), Ipv6OnlyOptionError>
    {
        if optlen == 0 { return Err(Ipv6OnlyOptionError::InvalidLength); }
        if !optval_present { return Err(Ipv6OnlyOptionError::NullValue); }
        if self.bound { return Err(Ipv6OnlyOptionError::Bound); }
        self.value = value;
        Ok(())
    }

    /// Commit bind and make the option immutable for this socket. # C: O(1)
    pub const fn bind(&mut self) { self.bound = true; }

    /// Return the option family for adapter dispatch. # C: O(1)
    pub const fn family(&self) -> u16 { self.family }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_defaults_to_only_and_accepts_one_byte_result_width() {
        let options = Ipv6OnlyOptions::new(AF_INET6).unwrap();
        assert_eq!(options.get(4, true), Ok((true, 1)));
    }

    #[test]
    fn set_is_valid_before_bind_and_persists_through_bind() {
        let mut options = Ipv6OnlyOptions::new(AF_INET6).unwrap();
        assert_eq!(options.set(false, 4, true), Ok(()));
        options.bind();
        assert_eq!(options.get(1, true), Ok((false, 1)));
    }

    #[test]
    fn bound_socket_cannot_change_ipv6_only_policy() {
        let mut options = Ipv6OnlyOptions::new(AF_INET6).unwrap();
        options.bind();
        assert_eq!(options.set(false, 4, true), Err(Ipv6OnlyOptionError::Bound));
        assert_eq!(Ipv6OnlyOptionError::Bound.wsa(), WsaError::InvalidArgument);
    }

    #[test]
    fn malformed_option_inputs_are_rejected_before_state_access() {
        let mut options = Ipv6OnlyOptions::new(AF_INET6).unwrap();
        assert_eq!(options.get(0, true), Err(Ipv6OnlyOptionError::InvalidLength));
        assert_eq!(options.set(false, 4, false), Err(Ipv6OnlyOptionError::NullValue));
        assert_eq!(Ipv6OnlyOptions::new(AF_INET).unwrap().family(), AF_INET);
        assert_eq!(Ipv6OnlyOptions::new(999), Err(Ipv6OnlyOptionError::WrongFamily));
    }
}
