//! Canonical passive TCP fingerprint database and matcher.

extern crate alloc;
use alloc::vec::Vec;

const MAX_GENRE: usize = 32;
const MAX_OPTS: usize = 40;
const MAX_OPT_BYTES: usize = 40;
const WSS_PLAIN: u32 = 0;
const WSS_MSS: u32 = 1;
const WSS_MTU: u32 = 2;
const WSS_MODULO: u32 = 3;
const TTL_TRUE: u8 = 0;
const TTL_LESS: u8 = 1;
const TTL_NOCHECK: u8 = 2;
const SMART_MSS_1: u32 = 1460;
const SMART_MSS_2: u32 = 1448;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct OsfOpt { kind: u16, length: u16, wc: u32, val: u32 }

#[derive(Clone, Debug, Eq, PartialEq)]
struct Fingerprint {
    wss_wc: u32,
    wss_val: u32,
    ttl: u8,
    df: bool,
    ss: u16,
    options: [OsfOpt; MAX_OPTS],
    opt_num: usize,
    genre: [u8; MAX_GENRE],
    version: [u8; MAX_GENRE],
    subtype: [u8; MAX_GENRE],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Error { Invalid, Exists, Missing }

const FINGER_WIRE_SIZE: usize = 592;
const OPT_WIRE_SIZE: usize = 12;

fn native_u16(raw: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(raw.get(at..at + 2)?.try_into().ok()?))
}

fn native_u32(raw: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(raw.get(at..at + 4)?.try_into().ok()?))
}

fn copy_name(raw: &[u8], out: &mut [u8; MAX_GENRE]) -> Option<()> {
    let end = raw.iter().position(|byte| *byte == 0)?;
    out[..end.min(MAX_GENRE)].copy_from_slice(&raw[..end.min(MAX_GENRE)]);
    Some(())
}

impl Fingerprint {
    fn from_wire(raw: &[u8]) -> Option<Self> {
        if raw.len() != FINGER_WIRE_SIZE { return None; }
        let wss_wc = native_u32(raw, 0)?;
        let wss_val = native_u32(raw, 4)?;
        let ttl = *raw.get(8)?;
        let df = *raw.get(9)? != 0;
        let ss = native_u16(raw, 10)?;
        let opt_num = native_u16(raw, 14)? as usize;
        if opt_num > MAX_OPTS || wss_wc >= WSS_MODULO + 1
            || (wss_wc == WSS_MODULO && wss_val == 0) { return None; }
        let mut genre = [0; MAX_GENRE];
        let mut version = [0; MAX_GENRE];
        let mut subtype = [0; MAX_GENRE];
        copy_name(raw.get(16..48)?, &mut genre)?;
        copy_name(raw.get(48..80)?, &mut version)?;
        copy_name(raw.get(80..112)?, &mut subtype)?;
        let mut options = [OsfOpt::default(); MAX_OPTS];
        let mut total = 0usize;
        for (index, option) in options.iter_mut().enumerate().take(opt_num) {
            let at = 112 + index * OPT_WIRE_SIZE;
            option.kind = native_u16(raw, at)?;
            option.length = native_u16(raw, at + 2)?;
            option.wc = native_u32(raw, at + 4)?;
            option.val = native_u32(raw, at + 8)?;
            if option.length == 0 || option.length as usize > MAX_OPT_BYTES
                || (option.kind == 2 && option.length < 4) { return None; }
            total = total.checked_add(option.length as usize)?;
            if total > MAX_OPT_BYTES { return None; }
        }
        Some(Self { wss_wc, wss_val, ttl, df, ss, options, opt_num, genre, version, subtype })
    }

    fn name(&self, with_version: bool, out: &mut [u8]) {
        let mut n = 0;
        for byte in self.genre.iter().copied().take_while(|byte| *byte != 0) {
            if n == out.len() { return; }
            out[n] = byte; n += 1;
        }
        if with_version && n < out.len() {
            out[n] = b':'; n += 1;
            for byte in self.version.iter().copied().take_while(|byte| *byte != 0) {
                if n == out.len() { return; }
                out[n] = byte; n += 1;
            }
        }
    }

    fn matches(&self, packet: &[u8], ttl_check: u8) -> bool {
        let Some(first) = packet.first() else { return false; };
        let Some(ihl) = ((*first & 0x0f) as usize).checked_mul(4) else { return false; };
        if ihl < 20 || packet.len() < ihl + 20 || packet[9] != 6 { return false; }
        let total_len = u16::from_be_bytes([packet[2], packet[3]]);
        let df = u16::from_be_bytes([packet[6], packet[7]]) & 0x4000 != 0;
        if df != self.df || total_len != self.ss { return false; }
        let ttl_ok = match ttl_check {
            TTL_TRUE => packet[8] == self.ttl,
            TTL_LESS => packet[8] <= self.ttl,
            TTL_NOCHECK => true,
            _ => false,
        };
        if !ttl_ok { return false; }
        let Some(tcp) = packet.get(ihl..ihl + 20) else { return false; };
        if tcp[13] & 0x02 == 0 || tcp[13] & 0x10 != 0 { return false; }
        let Some(tcp_len) = ((tcp[12] >> 4) as usize).checked_mul(4) else { return false; };
        if tcp_len < 20 || ihl + tcp_len > packet.len() { return false; }
        let Some(opts) = packet.get(ihl + 20..ihl + tcp_len) else { return false; };
        let fopts = self.options[..self.opt_num].iter()
            .fold(0usize, |sum, option| sum.saturating_add(option.length as usize));
        if fopts != opts.len() { return false; }
        let mut at = 0usize;
        let mut mss = 0u32;
        for option in self.options[..self.opt_num].iter() {
            let length = option.length as usize;
            if opts[at] as u16 != option.kind { return false; }
            if option.kind == 2 {
                if length < 4 { return false; }
                mss = u16::from_be_bytes([opts[at + 2], opts[at + 3]]) as u32;
            }
            at += length;
        }
        let window = u16::from_be_bytes([tcp[14], tcp[15]]) as u32;
        match self.wss_wc {
            WSS_PLAIN => self.wss_val == 0 || window == self.wss_val,
            WSS_MSS => window == self.wss_val * mss
                || window == self.wss_val * SMART_MSS_1
                || window == self.wss_val * SMART_MSS_2,
            WSS_MTU => window == self.wss_val * (mss + 40)
                || window == self.wss_val * (SMART_MSS_1 + 40)
                || window == self.wss_val * (SMART_MSS_2 + 40),
            WSS_MODULO => window % self.wss_val == 0,
            _ => false,
        }
    }
}

static FINGERPRINTS: sync::Spinlock<Vec<Fingerprint>, sync::Socket> =
    sync::Spinlock::new(Vec::new());

pub(crate) fn add(raw: &[u8], exclusive: bool) -> Result<(), Error> {
    let fingerprint = Fingerprint::from_wire(raw).ok_or(Error::Invalid)?;
    let mut fingers = FINGERPRINTS.lock();
    if fingers.iter().any(|old| old == &fingerprint) {
        return if exclusive { Err(Error::Exists) } else { Ok(()) };
    }
    fingers.push(fingerprint);
    Ok(())
}

pub(crate) fn remove(raw: &[u8]) -> Result<(), Error> {
    let fingerprint = Fingerprint::from_wire(raw).ok_or(Error::Invalid)?;
    let mut fingers = FINGERPRINTS.lock();
    let Some(index) = fingers.iter().position(|old| old == &fingerprint) else {
        return Err(Error::Missing);
    };
    fingers.remove(index);
    Ok(())
}

pub(crate) fn find(packet: &[u8], ttl: u8, with_version: bool, out: &mut [u8]) -> bool {
    FINGERPRINTS.lock().iter().find(|finger| finger.matches(packet, ttl))
        .map(|finger| { finger.name(with_version, out); true }).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{add, remove, find, FINGER_WIRE_SIZE, TTL_TRUE, WSS_PLAIN};
    use alloc::vec::Vec;
    use alloc::vec;

    fn put_ne_u16(raw: &mut [u8], at: usize, value: u16) {
        raw[at..at + 2].copy_from_slice(&value.to_ne_bytes());
    }

    fn put_ne_u32(raw: &mut [u8], at: usize, value: u32) {
        raw[at..at + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn fingerprint() -> Vec<u8> {
        let mut raw = vec![0; FINGER_WIRE_SIZE];
        put_ne_u32(&mut raw, 0, WSS_PLAIN);
        raw[8] = 64;
        put_ne_u16(&mut raw, 10, 40);
        raw[16..21].copy_from_slice(b"oxide");
        raw[48..53].copy_from_slice(b"test\0");
        raw[80..85].copy_from_slice(b"unit\0");
        raw
    }

    fn packet() -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[20 + 12] = 5 << 4;
        packet[20 + 13] = 2;
        packet
    }

    #[test]
    fn database_add_match_and_remove_follow_the_control_plane() {
        let raw = fingerprint();
        let packet = packet();
        add(&raw, true).unwrap();
        let mut out = [0u8; 16];
        assert!(find(&packet, TTL_TRUE, false, &mut out));
        assert_eq!(&out[..5], b"oxide");
        assert_eq!(remove(&raw), Ok(()));
        assert!(!find(&packet, TTL_TRUE, false, &mut out));
    }
}
