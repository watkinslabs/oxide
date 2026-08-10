//! What the delivery path does with a member a selection program named.
//!
//! The program itself is exercised where it runs; what is pinned here is the
//! step after it — that a named socket becomes the index of the candidate the
//! packet is handed to, that the group publishes its own identity to the run
//! so a program cannot name a socket outside it, and that every way of naming
//! nothing leaves the key on its own distribution instead of dropping traffic.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use sync::{Socket as SockLockClass, Spinlock};

use security::bpf::map::sockarray::{RunnerState, SockHandle};

use super::slot::{self, ReuseportSlot};
use crate::bpf_filter::{
    install_bpf_reuseport_runner, FilterKind, FilterProgram, ReuseportContext, ReuseportVerdict,
    SK_DROP, SK_PASS,
};
use crate::stack::{tcp_listener, TcpListenEntry};
use crate::{IpAddr, Ipv4Addr, NetStack};

const PORT: u16 = 49_711;
const SOURCE_PORT: u16 = 41_889;

/// The member the stub runner names, and the group state it was handed. A
/// runner is a bare function, so the test's intent reaches it through here.
static NAMED: Spinlock<Option<SockHandle>, SockLockClass> = Spinlock::new(None);
static SAW: Spinlock<Option<RunnerState>, SockLockClass> = Spinlock::new(None);

fn naming_runner(insns: &[u8], _maps: &[vfs::InodeRef], runner: RunnerState,
                 _ctx: ReuseportContext<'_>) -> ReuseportVerdict
{
    *SAW.lock() = Some(runner);
    let action = if insns == b"drop" { SK_DROP } else { SK_PASS };
    ReuseportVerdict { action, selected: NAMED.lock().clone() }
}

fn selection_program(insns: &[u8]) -> super::GroupProgram {
    super::GroupProgram::bare(FilterProgram {
        kind: FilterKind::SkReuseport, insns: insns.to_vec(),
    })
}

fn listen(stack: &NetStack, port: u16) -> Arc<TcpListenEntry> {
    stack.tcp_listen_ip_with(IpAddr::V4(Ipv4Addr::LOOPBACK), port, false, true)
        .expect("reuseport listeners share the key")
}

fn join(stack: &NetStack, listener: &Arc<TcpListenEntry>) -> ReuseportSlot {
    let member = slot::new_slot();
    stack.join_tcp_reuseport(listener, &member);
    member
}

fn names(listener: &Arc<TcpListenEntry>) {
    let object: Arc<dyn Any + Send + Sync> = listener.clone();
    let cell: Arc<dyn Any + Send + Sync> = listener.reuseport_group.clone();
    *NAMED.lock() = Some(SockHandle {
        hashed: Arc::downgrade(&object), cell: Arc::downgrade(&cell),
        cookie: 1, protocol: crate::addr::IpProto::Tcp as u8,
        family: crate::socket_args::AF_INET as u16,
    });
}

fn chosen(bucket: &[Arc<TcpListenEntry>]) -> Option<usize> {
    tcp_listener::select_listener_index(
        bucket, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), SOURCE_PORT, PORT, b"segment", 0)
}

/// Three listeners on one key, with a selection program installed.
fn fixture(stack: &NetStack, insns: &[u8]) -> Vec<Arc<TcpListenEntry>> {
    install_bpf_reuseport_runner(naming_runner);
    let bucket: Vec<Arc<TcpListenEntry>> = (0..3).map(|_| listen(stack, PORT)).collect();
    let members: Vec<ReuseportSlot> = bucket.iter().map(|l| join(stack, l)).collect();
    slot::group(&members[0]).expect("one group for the key").attach_prog(selection_program(insns));
    *NAMED.lock() = None;
    *SAW.lock() = None;
    bucket
}

#[test]
fn a_named_member_becomes_the_candidate_the_packet_is_handed_to() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let bucket = fixture(&stack, b"select");
    for index in 0..bucket.len() {
        names(&bucket[index]);
        assert_eq!(chosen(&bucket), Some(index), "the named member takes the segment");
    }
}

#[test]
fn the_group_publishes_its_own_identity_to_the_program_that_runs_for_it() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let bucket = fixture(&stack, b"select");
    let group = slot::group(&bucket[0].reuseport_group).expect("the key's group");
    let _ = chosen(&bucket);
    let saw = SAW.lock().expect("the runner was reached");
    assert_eq!(saw.group_id, group.id(), "so a program cannot name a socket outside this key");
    assert_eq!(saw.protocol, crate::addr::IpProto::Tcp as u8);
    assert_eq!(saw.family, crate::socket_args::AF_INET as u16);
    // Two keys are two identities.
    let elsewhere = listen(&stack, PORT + 1);
    let other = join(&stack, &elsewhere);
    assert_ne!(slot::group(&other).expect("its own group").id(), group.id());
}

#[test]
fn naming_nobody_leaves_the_key_on_its_own_distribution() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let bucket = fixture(&stack, b"select");
    let hashed = tcp_listener::select_reuseport_listener(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), SOURCE_PORT, PORT, bucket.len());
    assert_eq!(chosen(&bucket), Some(hashed), "a program that names nobody decides nothing");
}

#[test]
fn naming_a_socket_that_is_not_a_candidate_here_leaves_the_distribution_alone() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let bucket = fixture(&stack, b"select");
    let stranger = listen(&stack, PORT + 2);
    names(&stranger);
    let hashed = tcp_listener::select_reuseport_listener(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), SOURCE_PORT, PORT, bucket.len());
    assert_eq!(chosen(&bucket), Some(hashed),
        "the segment still belongs to this key, so it is distributed, not dropped");
}

#[test]
fn a_named_member_whose_socket_has_gone_leaves_the_distribution_alone() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let bucket = fixture(&stack, b"select");
    let doomed = listen(&stack, PORT + 3);
    names(&doomed);
    drop(doomed);
    let hashed = tcp_listener::select_reuseport_listener(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), SOURCE_PORT, PORT, bucket.len());
    assert_eq!(chosen(&bucket), Some(hashed));
}

#[test]
fn a_refused_segment_reaches_nobody_even_when_a_member_was_named() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let bucket = fixture(&stack, b"drop");
    names(&bucket[1]);
    assert_eq!(chosen(&bucket), None, "the action outranks the selection");
}


/// A selection runs in softirq at the tail of a receive path. Reading which
/// group a stored socket is in must therefore not take a reference to the
/// socket: being its last owner there would run the socket's whole teardown —
/// file, mount, superblock writeback — from inside a program run. The group is
/// reached through the socket's own reuseport cell instead, and this pins that
/// by answering for a socket whose object is already gone.
mod reading_the_group {
    use super::*;
    use crate::sock::sockarray;

    #[test]
    fn the_group_is_readable_without_any_reference_to_the_socket() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = NetStack::new();
        let listener = listen(&stack, 49_733);
        let cell = join(&stack, &listener);
        let group = slot::group(&cell).expect("the key allocated a group");

        // A handle whose socket object is already unreachable, but whose
        // reuseport cell is not.
        let gone: Arc<dyn Any + Send + Sync> = Arc::new(0u8);
        let named: Arc<dyn Any + Send + Sync> = cell.clone();
        let handle = SockHandle {
            hashed: Arc::downgrade(&gone),
            cell: Arc::downgrade(&named),
            cookie: 5,
            protocol: crate::addr::IpProto::Tcp as u8,
            family: crate::socket_args::AF_INET as u16,
        };
        drop(gone);
        assert!(handle.upgrade().is_none(), "nothing here holds the socket");

        let state = sockarray::state_of(&handle).expect("the group still answers");
        assert_eq!(state.group_id, group.id());
        assert_eq!(state.protocol, crate::addr::IpProto::Tcp as u8);
        assert_eq!(state.family, crate::socket_args::AF_INET as u16);
    }

    #[test]
    fn a_socket_that_left_every_group_answers_for_none() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = NetStack::new();
        let listener = listen(&stack, 49_734);
        let cell = join(&stack, &listener);
        slot::leave(&cell);
        let named: Arc<dyn Any + Send + Sync> = cell.clone();
        let handle = SockHandle {
            hashed: Arc::downgrade(&named), cell: Arc::downgrade(&named),
            cookie: 5, protocol: crate::addr::IpProto::Tcp as u8,
            family: crate::socket_args::AF_INET as u16,
        };
        assert!(sockarray::state_of(&handle).is_none());
    }
}
