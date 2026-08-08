// `IPV6_FLOWINFO_SEND`: the `sin6_flowinfo` a supplied destination carries.
//
// The word rides between the port and the address of every `sockaddr_in6`, so
// a caller who never initialised it must not have it acted on. The option is
// the gate; with it set, the destination's flow information overrides for that
// one message whatever a connect settled, and an ancillary label the same
// message named still outranks both.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{Message, SendContext, SendFile};
use crate::send::{InetPrepared, PreparedSend};

const FLOWINFO: u32 = 0x0abc_de12;

fn task(tid: u32) -> sched::Task {
    sched::Task::new(tid, "sndflow", sched::SchedClass::Normal { weight: 1024 })
}

fn udp6(namespace: &network_namespace::NetworkNamespaceRef)
    -> (Arc<net::sock::InetSocket>, SendFile)
{
    let socket = Arc::new(net::sock::InetSocket::new_udp6_in(namespace.clone()));
    let inode = net::sock::make_inet_socket_inode(socket.clone());
    let dentry = vfs::Dentry::new(None, String::from("udp6"), inode.clone());
    (socket, SendFile::new(vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR)))
}

/// `sockaddr_in6` for `2001:db8::1`, carrying `flowinfo` in network order.
fn addr6(flowinfo: u32) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; 28];
    bytes[..2].copy_from_slice(&(net::socket_args::AF_INET6 as u16).to_ne_bytes());
    bytes[2..4].copy_from_slice(&53u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&flowinfo.to_be_bytes());
    bytes[8..10].copy_from_slice(&[0x20, 0x01]);
    bytes[10..12].copy_from_slice(&[0x0d, 0xb8]);
    bytes[23] = 1;
    bytes
}

fn settled(socket_flowinfo_send: bool, supplied: u32) -> Option<u32> {
    let _unpoliced = crate::test_support::unpoliced();
    let owner = network_namespace::initial();
    let (socket, target) = udp6(&owner);
    socket.opts.ipv6.set_flag(net::sock_opts::sol_ipv6::flag::SNDFLOW, socket_flowinfo_send);
    let task = task(911);
    let ctx = SendContext::with_sandbox(&task, None);
    let message = Message { requested_len: 4, payload: alloc::vec![0u8; 4],
        name: Some(addr6(supplied)), ..Message::default() };
    match crate::send::prepare(&ctx, &target, &message, 0).expect("prepared") {
        PreparedSend::Inet(InetPrepared::Transport(_, control)) => control.raw6.flowinfo,
        _ => panic!("a UDP6 send prepares a transport message"),
    }
}

#[test]
fn a_destination_flow_word_is_ignored_until_the_socket_asks_to_send_one() {
    assert_eq!(settled(false, FLOWINFO), None,
        "an uninitialised sin6_flowinfo must not reach the wire");
}

#[test]
fn the_option_lets_the_destination_name_this_messages_flow_information() {
    assert_eq!(settled(true, FLOWINFO), Some(FLOWINFO));
    // The version nibble is never the caller's.
    assert_eq!(settled(true, 0xf000_0007), Some(7));
}
