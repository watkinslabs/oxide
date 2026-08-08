// The ONE send-side ancillary walk.
//
// Every family's send admission rule differs in WHICH control messages it
// accepts, never in how the stream is framed. Framing was nevertheless written
// out twice — once for the SCM parser and once for the IP parser — and the two
// copies were free to disagree about the minimum header, the `controllen`
// bound, the alignment step, and the difference between a message that FAILS
// the walk and one that merely ENDS it. This cursor states those rules once and
// every admission rule iterates it.
//
// The framing contract: a header is read only while a whole one remains; a
// declared length shorter than the header, or longer than the bytes left,
// fails the walk with EINVAL; the step to the next header is the declared
// length rounded up to the alignment, and a step that leaves less than one
// header simply ends the walk.

use crate::{Error, KResult};

pub(crate) const SOL_SOCKET: i32 = 1;

/// One ancillary message: its level, its type, and its payload — the declared
/// length minus the header.
pub(crate) struct Cmsg<'a> {
    pub level: i32,
    pub kind: i32,
    pub data: &'a [u8],
}

pub(crate) struct CmsgWalk<'a> {
    control: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> CmsgWalk<'a> {
    /// Walk one native-layout control buffer. # C: O(1)
    pub(crate) fn new(control: &'a [u8]) -> Self { Self { control, offset: 0, done: false } }
}

fn i32_at(bytes: &[u8], at: usize) -> i32 { i32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) }
fn u64_at(bytes: &[u8], at: usize) -> u64 { u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap()) }

impl<'a> Iterator for CmsgWalk<'a> {
    type Item = KResult<Cmsg<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done { return None; }
        let control: &'a [u8] = self.control;
        let at = self.offset;
        if control.len().saturating_sub(at) < crate::ids::CMSG_HEADER_LEN {
            self.done = true;
            return None;
        }
        let len = match usize::try_from(u64_at(control, at)) {
            Ok(len) if len >= crate::ids::CMSG_HEADER_LEN && len <= control.len() - at => len,
            _ => { self.done = true; return Some(Err(Error::Einval)); }
        };
        let item = Cmsg {
            level: i32_at(control, at + 8),
            kind: i32_at(control, at + 12),
            data: &control[at + crate::ids::CMSG_HEADER_LEN..at + len],
        };
        let Some(aligned) = len.checked_add(crate::ids::CMSG_ALIGN_MASK) else {
            self.done = true; return Some(Err(Error::Einval));
        };
        let aligned = aligned & !crate::ids::CMSG_ALIGN_MASK;
        match at.checked_add(aligned) {
            Some(next) if next <= control.len() => self.offset = next,
            _ => self.done = true,
        }
        Some(Ok(item))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn entry(level: i32, kind: i32, data: &[u8]) -> Vec<u8> {
        let len = crate::ids::CMSG_HEADER_LEN + data.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(len as u64).to_ne_bytes());
        out.extend_from_slice(&level.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(data);
        while out.len() & crate::ids::CMSG_ALIGN_MASK != 0 { out.push(0); }
        out
    }

    #[test]
    fn two_entries_are_walked_with_their_own_payloads() {
        let mut buf = entry(SOL_SOCKET, 1, &[1, 2, 3, 4]);
        buf.extend_from_slice(&entry(0, 2, &[9, 9, 9, 9]));
        let seen: Vec<(i32, i32, usize)> = CmsgWalk::new(&buf)
            .map(|item| { let c = item.unwrap(); (c.level, c.kind, c.data.len()) }).collect();
        assert_eq!(seen, alloc::vec![(SOL_SOCKET, 1, 4), (0, 2, 4)]);
    }

    #[test]
    fn a_partial_trailing_header_ends_the_walk_without_an_error() {
        let mut buf = entry(SOL_SOCKET, 1, &[0; 4]);
        buf.extend_from_slice(&[0u8; 8]);
        let seen: Vec<_> = CmsgWalk::new(&buf).collect();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].is_ok());
    }

    #[test]
    fn a_declared_length_past_the_buffer_fails_the_walk() {
        let mut buf = entry(SOL_SOCKET, 1, &[0; 4]);
        buf[..8].copy_from_slice(&(4096u64).to_ne_bytes());
        let seen: Vec<_> = CmsgWalk::new(&buf).collect();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].as_ref().err(), Some(&Error::Einval));
    }

    #[test]
    fn a_declared_length_below_the_header_fails_the_walk() {
        let mut buf = entry(SOL_SOCKET, 1, &[0; 4]);
        buf[..8].copy_from_slice(&(4u64).to_ne_bytes());
        assert_eq!(CmsgWalk::new(&buf).next().unwrap().err(), Some(Error::Einval));
    }

    #[test]
    fn a_buffer_shorter_than_one_header_yields_nothing() {
        assert!(CmsgWalk::new(&[0u8; 8]).next().is_none());
        assert!(CmsgWalk::new(&[]).next().is_none());
    }

    #[test]
    fn an_overflowing_length_fails_rather_than_wrapping() {
        let mut buf = entry(SOL_SOCKET, 1, &[0; 4]);
        buf[..8].copy_from_slice(&u64::MAX.to_ne_bytes());
        assert_eq!(CmsgWalk::new(&buf).next().unwrap().err(), Some(Error::Einval));
    }
}
