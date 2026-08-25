use super::*;

/// A real client connection whose SYN is built by the client mechanism and
/// delivered to a real listener, so both halves of the ladder run against one
/// another over the same bytes.
fn client_conn(client_port: u16, port: u16) -> crate::tcp_conn::TcpConn {
    crate::tcp_conn::TcpConn::new_client(
        crate::tcp_conn::Endpoint { ip: IpAddr::V4(SERVER), port: client_port },
        crate::tcp_conn::Endpoint { ip: IpAddr::V4(SERVER), port }, CLIENT_SEQ)
}

/// Deliver a segment the client built, and return the listener's child.
fn deliver_client(stack: &NetStack, iface: NetIfaceId, port: u16, client_port: u16,
                  seg: &[u8]) -> Option<Server>
{
    stack.deliver_tcp_packet(0, iface, IpAddr::V4(SERVER), IpAddr::V4(SERVER), seg, seg)
        .expect("deliver the client SYN");
    let key = TcpKey {
        local_ip: IpAddr::V4(SERVER), local_port: port,
        remote_ip: IpAddr::V4(SERVER), remote_port: client_port,
    };
    Server::of(stack.inet_tables(0).tcp_conns.lock().get(&key).cloned())
}

#[test]
fn a_client_request_and_a_server_offer_meet_over_real_segments() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _listener) = fixture(&stack, 730, 4);
    let mut client = client_conn(50_730, 730);

    // The client asks for a cookie the way a cache miss does.
    let (syn_seg, carried) = client.active_open_fastopen(Some(Cookie::request(false)), b"GET /")
        .expect("the open");
    let server = deliver_client(&stack, iface, 730, 50_730, &syn_seg).expect("a request");
    assert_eq!(carried, 5);

    // The listener declined the data — no cookie was presented — and offered
    // one instead. The client learns it and still owes its bytes.
    let FastOpen::Cookie(offered) = synack_option(&server)
        else { unreachable!("a cookie request is answered") };
    let synack = server.synack();
    client.input(IpAddr::V4(SERVER), IpAddr::V4(SERVER), &synack).expect("the answer");
    assert_eq!(client.state, TcpState::Established, "the connection opened either way");
    let learned = client.fastopen_learned.expect("the answer was read");
    assert_eq!(learned.cookie, Some(offered));
    assert!(learned.failed, "the listener took none of the data, so it is still owed");
    assert_eq!(client.retx_q.iter().map(|s| s.payload.len()).sum::<usize>(), 5);
}

#[test]
fn a_client_presenting_the_offered_cookie_has_its_data_taken_and_acknowledged() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, listener) = fixture(&stack, 731, 4);
    let offered = obtain_cookie(&stack, iface, 731, 50_731);

    let mut client = client_conn(50_732, 731);
    let (syn_seg, carried) = client.active_open_fastopen(Some(offered), b"GET /")
        .expect("the open");
    assert_eq!(carried, 5);
    let server = deliver_client(&stack, iface, 731, 50_732, &syn_seg).expect("a child");
    assert!(stack.tcp_accept(&listener).is_some(), "the child is acceptable at its SYN");

    let synack = server.synack();
    client.input(IpAddr::V4(SERVER), IpAddr::V4(SERVER), &synack).expect("the answer");
    assert!(client.syn_data_acked, "the data rode the SYN and was acknowledged with it");
    assert!(client.retx_q.is_empty(), "nothing is owed");
    assert!(!client.fastopen_learned.expect("the answer was read").failed);
}

#[test]
fn a_client_whose_cookie_the_listener_rejects_still_gets_a_connection() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let stack = NetStack::new();
    let (iface, _listener) = fixture(&stack, 732, 4);
    let mut client = client_conn(50_733, 732);
    // A cookie from some other server: it cannot verify here.
    let (syn_seg, _) = client.active_open_fastopen(Some(Cookie::minted([0xee; 8], false)), b"GET /")
        .expect("the open");
    let server = deliver_client(&stack, iface, 732, 50_733, &syn_seg).expect("a request");

    let synack = server.synack();
    client.input(IpAddr::V4(SERVER), IpAddr::V4(SERVER), &synack).expect("the answer");
    assert_eq!(client.state, TcpState::Established);
    let learned = client.fastopen_learned.expect("the answer was read");
    assert!(learned.cookie.is_some(),
        "the listener hands back a usable cookie rather than punishing the client");
    assert!(learned.failed, "and the data is retransmitted on the ordinary path");
}

