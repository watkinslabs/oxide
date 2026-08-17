// The chip: bank inventory plus a transport, and the operations that need both.
//
// This is the piece that makes a measurement reach hardware. Everything under
// it already existed — `codec::cmds` marshals the commands, `tis`/`crb` move
// the bytes — but nothing owned the pair, so the only way to "extend" a PCR
// was to mutate a value the kernel held, which reached no chip at all.
//
// The reference's extend is: validate the caller's digest set against the
// banks the chip reported, marshal one command carrying a digest per bank, and
// transmit. Its integrity-protected variant wraps that in an HMAC session
// derived through a salted ECDH exchange; its `disable_pcr_integrity` variant
// authorises with an empty password and is otherwise identical. This
// implements the password variant, which is a supported upstream path rather
// than a shortcut invented here — the session layer needs KDFa, HMAC and
// P-256, and is recorded as its own work.

use alloc::vec;
use alloc::vec::Vec;

use crate::codec::{cmds, CodecError, Response};
use crate::pcr::{AllocatedBanks, PcrError};
use crate::rc::Rc;

/// Moving command bytes to a chip and a response back.
///
/// Both wire transports satisfy this; a test satisfies it with a script. The
/// chip layer is written against this rather than against either transport so
/// the command construction is exercised without hardware.
pub trait Transport {
    /// Send one marshalled command. # C: O(len)
    fn send(&mut self, cmd: &[u8]) -> Result<(), TransportError>;
    /// Receive one response into `out`, returning its length. # C: O(len)
    fn recv(&mut self, out: &mut [u8]) -> Result<usize, TransportError>;
}

/// The transport could not carry the exchange.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TransportError;

/// Why a chip operation failed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ChipError {
    /// The digest set does not match the banks the chip reported.
    Pcr(PcrError),
    /// The command could not be marshalled or the response not parsed.
    Codec(CodecError),
    /// The transport failed to carry the exchange.
    Transport,
    /// The chip answered, and refused.
    Tpm(Rc),
}

impl From<PcrError> for ChipError { fn from(e: PcrError) -> Self { ChipError::Pcr(e) } }
impl From<CodecError> for ChipError { fn from(e: CodecError) -> Self { ChipError::Codec(e) } }
impl From<TransportError> for ChipError { fn from(_: TransportError) -> Self { ChipError::Transport } }

/// Largest response this layer will accept from a chip.
const RSP_BUF: usize = crate::limits::TPM_BUFSIZE;

/// A TPM: the banks it reported allocated, and the way to talk to it.
pub struct Chip<T: Transport> {
    banks: AllocatedBanks,
    phy: T,
}

impl<T: Transport> Chip<T> {
    /// A chip with the banks it reported, reachable over `phy`. # C: O(banks)
    pub fn new(banks: AllocatedBanks, phy: T) -> Self { Chip { banks, phy } }

    /// The banks the chip reported allocated. # C: O(1)
    pub fn banks(&self) -> &AllocatedBanks { &self.banks }

    /// Extend register `idx` in every allocated bank.
    ///
    /// `digests` pairs an algorithm identifier with the measurement computed
    /// under it. Every allocated bank must appear: the chip extends all of
    /// them from one command, so a caller supplying fewer would leave the
    /// omitted banks recording a different history. The set is checked before
    /// anything is marshalled, so a rejected request sends no bytes.
    /// # C: O(banks + digest bytes)
    pub fn pcr_extend(&mut self, idx: usize, digests: &[(u16, &[u8])]) -> Result<(), ChipError> {
        self.banks.check_extend(idx, digests)?;
        let cmd = cmds::pcr_extend(idx, digests)?;
        self.transmit(&cmd).map(|_| ())
    }

    /// Send one command and return its response body, refusing a non-success
    /// response code rather than handing back a body the chip did not fill.
    /// # C: O(len)
    fn transmit(&mut self, cmd: &[u8]) -> Result<Vec<u8>, ChipError> {
        self.phy.send(cmd)?;
        let mut buf = vec![0u8; RSP_BUF];
        let n = self.phy.recv(&mut buf)?;
        buf.truncate(n);
        let rsp = Response::parse(&buf)?;
        if !rsp.rc().is_success() { return Err(ChipError::Tpm(rsp.rc())); }
        Ok(rsp.raw_body().to_vec())
    }
}
