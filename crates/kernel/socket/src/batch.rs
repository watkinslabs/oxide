use alloc::sync::Arc;

use crate::{Error, ImportMode, KResult, Message, SendContext, SendFile, SendKind};
use crate::send::{InetPrepared, PreparedSend, prepare, send_prepared, send_retained};

pub const UIO_MAXIOV: u32 = 1024;
pub const MSG_BATCH: u32 = 0x4_0000;
pub const MSG_CMSG_COMPAT: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchSpec {
    pub len: u32,
    pub flags: u32,
}

pub trait BatchIo {
    /// Fetch one open file description for the complete batch. # C: O(1)
    fn file(&mut self) -> KResult<Arc<vfs::File>>;
    /// Import exactly one message into kernel-owned memory. # C: O(message bytes)
    fn import(&mut self, index: u32, mode: ImportMode) -> KResult<Message>;
    /// Import one entry's metadata, name, and control, or select full import. # C: O(envelope)
    fn import_envelope(&mut self, _index: u32) -> KResult<Option<Message>> { Ok(None) }
    /// Complete one entry's payload import after target preparation. # C: O(payload)
    fn import_payload(&mut self, _index: u32, _message: &mut Message) -> KResult<()> {
        Err(Error::Eio)
    }
    /// Publish one completed message length to the ABI destination. # C: O(1)
    fn publish(&mut self, index: u32, len: u32) -> KResult<()>;
}

/// Send a lazy imported batch through one retained target. # C: O(messages + bytes)
pub fn send_batch<I: BatchIo>(ctx: &SendContext<'_>, spec: BatchSpec, io: &mut I) -> KResult<u32>
{
    if spec.flags & MSG_CMSG_COMPAT != 0 { return Err(Error::Einval); }
    let target = SendFile::new(io.file()?);
    if !target.is_socket() { return Err(Error::Enotsock); }
    let len = spec.len.min(UIO_MAXIOV);
    let mode = match target.kind() {
        SendKind::Inet(socket) if spec.flags as u64 & net::uapi::MSG_OOB != 0
            && matches!(*socket.kind.lock(), net::sock::SockKind::Raw4(_)
                | net::sock::SockKind::Raw6(_)) => ImportMode::RawOobEnvelope,
        SendKind::Vsock(_) if spec.flags as u64 & net::uapi::MSG_OOB != 0 =>
            ImportMode::RawOobEnvelope,
        _ => ImportMode::Full,
    };
    let mut sent = 0u32;
    for index in 0..len {
        let flags = if index + 1 < len { spec.flags | MSG_BATCH } else { spec.flags };
        let attempt = (|| {
            if mode == ImportMode::RawOobEnvelope {
                return send_retained(ctx, &target, io.import(index, mode)?, flags,
                    crate::send::unresolved_address());
            }
            if let Some(mut message) = io.import_envelope(index)? {
                let prepared = prepare(ctx, &target, &message, flags)?;
                let tx_ring = matches!((&prepared, target.kind()),
                    (PreparedSend::Inet(InetPrepared::Packet), SendKind::Inet(socket))
                        if socket.has_packet_tx_ring());
                if !tx_ring { io.import_payload(index, &mut message)?; }
                return send_prepared(ctx, &target, message, flags, prepared);
            }
            send_retained(ctx, &target, io.import(index, mode)?, flags,
                crate::send::unresolved_address())
        })();
        let outcome = match attempt {
            Ok(outcome) => outcome,
            Err(error) => return if sent == 0 { Err(error) } else { Ok(sent) },
        };
        if let Err(error) = io.publish(index, outcome.bytes as u32) {
            return if sent == 0 { Err(error) } else { Ok(sent) };
        }
        sent += 1;
        if !outcome.complete { break; }
    }
    Ok(sent)
}
