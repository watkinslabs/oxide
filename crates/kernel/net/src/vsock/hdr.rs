// virtio-vsock packet header (virtio 1.2 §5.10.6 `virtio_vsock_hdr`)
// + protocol op/type/flag constants. PURE — host-testable encode/decode,
// no DMA, no kernel deps. The driver crate (drv-virtio-vsock) owns the
// ring; this module is the wire format both ends agree on.
//
// Header layout (44 bytes, all little-endian on the wire):
//   off  0  src_cid   u64
//   off  8  dst_cid   u64
//   off 16  src_port  u32
//   off 20  dst_port  u32
//   off 24  len       u32   (payload byte count following the header)
//   off 26  type      u16   (28: at off 28; see field order below)
// NOTE the on-wire order is: src_cid, dst_cid, src_port, dst_port, len,
//   type, op, flags, buf_alloc, fwd_cnt — encoded explicitly below.

/// Header size on the wire. # C: O(1)
pub const VSOCK_HDR_LEN: usize = 44;

/// `type` field for the byte-stream transport.
pub const VIRTIO_VSOCK_TYPE_STREAM: u16 = 1;
/// `type` field for record-preserving `SOCK_SEQPACKET` transport.
pub const VIRTIO_VSOCK_TYPE_SEQPACKET: u16 = 2;

/// Virtio feature bit advertising record-preserving `SOCK_SEQPACKET`.
/// The driver must not negotiate this until the complete record owner is live.
pub const VIRTIO_VSOCK_F_SEQPACKET: u32 = 1;
/// Negotiated-feature mask for `VIRTIO_VSOCK_F_SEQPACKET`.
pub const VIRTIO_VSOCK_F_SEQPACKET_MASK: u64 = 1u64 << VIRTIO_VSOCK_F_SEQPACKET;

/// `op` field values (virtio 1.2 §5.10.6.1).
pub const VIRTIO_VSOCK_OP_INVALID:        u16 = 0;
pub const VIRTIO_VSOCK_OP_REQUEST:        u16 = 1;
pub const VIRTIO_VSOCK_OP_RESPONSE:       u16 = 2;
pub const VIRTIO_VSOCK_OP_RST:            u16 = 3;
pub const VIRTIO_VSOCK_OP_SHUTDOWN:       u16 = 4;
pub const VIRTIO_VSOCK_OP_RW:             u16 = 5;
pub const VIRTIO_VSOCK_OP_CREDIT_UPDATE:  u16 = 6;
pub const VIRTIO_VSOCK_OP_CREDIT_REQUEST: u16 = 7;

/// `flags` for OP_SHUTDOWN: which directions the peer is closing.
pub const VIRTIO_VSOCK_SHUTDOWN_RCV:  u32 = 1;
pub const VIRTIO_VSOCK_SHUTDOWN_SEND: u32 = 2;

/// `OP_RW` flag: this fragment terminates one `SOCK_SEQPACKET` message.
pub const VIRTIO_VSOCK_SEQ_EOM: u32 = 1;
/// `OP_RW` flag: this fragment terminates one `SOCK_SEQPACKET` record.
pub const VIRTIO_VSOCK_SEQ_EOR: u32 = 2;

/// Well-known CIDs. Host is always 2; CID 0/1 reserved.
pub const VMADDR_CID_HOST: u64 = 2;
pub const VMADDR_CID_ANY:  u64 = 0xFFFF_FFFF;

/// Decoded virtio_vsock_hdr. `len` is the payload length that follows
/// the header in the same buffer. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct VsockHdr {
    pub src_cid:   u64,
    pub dst_cid:   u64,
    pub src_port:  u32,
    pub dst_port:  u32,
    pub len:       u32,
    pub typ:       u16,
    pub op:        u16,
    pub flags:     u32,
    pub buf_alloc: u32,
    pub fwd_cnt:   u32,
}

impl VsockHdr {
    /// Encode the header into a 44-byte little-endian buffer.
    /// # C: O(1)
    pub fn encode(&self) -> [u8; VSOCK_HDR_LEN] {
        let mut b = [0u8; VSOCK_HDR_LEN];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.typ.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }

    /// Decode a header from the front of `b`. None if `b` is short.
    /// # C: O(1)
    pub fn decode(b: &[u8]) -> Option<VsockHdr> {
        if b.len() < VSOCK_HDR_LEN { return None; }
        let r64 = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let r32 = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let r16 = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        Some(VsockHdr {
            src_cid:   r64(0),
            dst_cid:   r64(8),
            src_port:  r32(16),
            dst_port:  r32(20),
            len:       r32(24),
            typ:       r16(28),
            op:        r16(30),
            flags:     r32(32),
            buf_alloc: r32(36),
            fwd_cnt:   r32(40),
        })
    }
}
