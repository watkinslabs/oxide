use alloc::sync::Arc;

struct PacketRingBacking {
    pin: net::sock::PacketRingMmap,
    file: Arc<vfs::File>,
}

impl vmm::FileBacking for PacketRingBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, ()> { Err(()) }

    fn size_hint(&self) -> u64 { self.pin.len() }

    fn ino(&self) -> u64 { self.file.inode().ino() }

    fn shared_frame(&self, off: u64) -> Option<u64> { self.pin.frame(off) }

    fn direct_frame(&self, off: u64) -> Option<u64> { self.pin.frame(off) }
}

/// Resolve an AF_PACKET ring mapping while retaining its memory owner. # C: O(1)
pub(crate) fn backing(file: &Arc<vfs::File>, off: u64, len: u64, flags: u64)
    -> Option<Result<Arc<dyn vmm::FileBacking>, i64>>
{
    let inode = file.inode();
    let socket = net::sock::inet_arc_from_inode(inode)?;
    if !matches!(*socket.kind.lock(), net::sock::SockKind::Packet { .. }) { return None; }
    match pmm::mmap_flags::map_type(flags) {
        Ok(_) => {},
        Err(error) => return Some(Err(error)),
    }
    let pin = match socket.packet_ring_mmap(off, len) {
        Ok(pin) => pin,
        Err(error) => return Some(Err(crate::net_common::errno_from_neterr(error))),
    };
    Some(Ok(Arc::new(PacketRingBacking { pin, file: file.clone() })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscall::errno::Errno;

    fn fixture() -> (Arc<net::sock::InetSocket>, Arc<vfs::File>) {
        let socket = Arc::new(net::sock::InetSocket::new_packet(net::eth_p::ALL, 3));
        socket.set_packet_ring(net::sock::PacketRingKind::Rx,
            net::sock::PacketRingRequest {
                block_size: 4096, block_nr: 1, frame_size: 256, frame_nr: 16,
                ..net::sock::PacketRingRequest::default()
            }).unwrap();
        let inode = net::sock::make_inet_socket_inode(socket.clone());
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("packet"), inode.clone());
        (socket, vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR))
    }

    #[test]
    fn shared_backing_clone_pins_ring_until_last_vma_owner_drops() {
        let (socket, file) = fixture();
        let backing = backing(&file, 0, 4096, pmm::mmap_flags::MAP_SHARED)
            .unwrap().unwrap();
        assert!(backing.shared_frame(0).is_some());
        let fork_or_split = backing.clone();
        drop(backing);
        assert_eq!(socket.set_packet_ring(net::sock::PacketRingKind::Rx,
            net::sock::PacketRingRequest::default()), Err(net::NetError::Ebusy));
        drop(fork_or_split);
        socket.set_packet_ring(net::sock::PacketRingKind::Rx,
            net::sock::PacketRingRequest::default()).unwrap();
    }

    #[test]
    fn packet_mmap_accepts_linux_private_alias_and_rejects_inexact_shape() {
        let (_socket, file) = fixture();
        let private = backing(&file, 0, 4096, pmm::mmap_flags::MAP_PRIVATE)
            .unwrap().unwrap();
        assert_eq!(private.direct_frame(0), private.shared_frame(0));
        drop(private);
        assert_eq!(backing(&file, 4096, 4096, pmm::mmap_flags::MAP_SHARED)
            .unwrap().err(), Some(-(Errno::Einval.as_i32() as i64)));
        assert_eq!(backing(&file, 0, 8192, pmm::mmap_flags::MAP_SHARED)
            .unwrap().err(), Some(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn packet_vma_retains_socket_file_until_final_backing_drop() {
        let (socket, file) = fixture();
        let weak = Arc::downgrade(&socket);
        let backing = backing(&file, 0, 4096, pmm::mmap_flags::MAP_SHARED)
            .unwrap().unwrap();
        drop(file); drop(socket);
        assert!(weak.upgrade().is_some(), "VMA backing retains the open socket file");
        drop(backing);
        assert!(weak.upgrade().is_none(), "final VMA drop releases the socket file");
    }
}
