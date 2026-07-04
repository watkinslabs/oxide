use super::*;
    #[test]
    fn port_parsing() {
        assert_eq!(parse_port(b"80"), Some(80));
        assert_eq!(parse_port(b""), Some(0));
        assert_eq!(parse_port(b"https"), Some(443));
        assert_eq!(parse_port(b"99999"), None);
        assert_eq!(parse_port(b"nope"), None);
    }

    #[test]
    fn port_parsing_uses_services_by_socktype() {
        let services = b"\
            custom 1234/tcp custom-alias\n\
            custom 4321/udp\n\
            onlyudp 5353/udp mdns-alias\n";

        assert_eq!(parse_port_with_services(b"custom", SOCK_STREAM, services), Some(1234));
        assert_eq!(parse_port_with_services(b"custom", SOCK_DGRAM, services), Some(4321));
        assert_eq!(parse_port_with_services(b"custom-alias", SOCK_STREAM, services), Some(1234));
        assert_eq!(parse_port_with_services(b"mdns-alias", SOCK_DGRAM, services), Some(5353));
        assert_eq!(parse_port_with_services(b"onlyudp", SOCK_STREAM, services), None);
        assert_eq!(parse_port_with_services(b"custom", 99, services), None);
    }

    #[test]
    fn numeric_v4() {
        let (fam, b, len) = fill_sockaddr(b"127.0.0.1", 80, 0).unwrap();
        assert_eq!(fam, AF_INET as i32);
        assert_eq!(len, 16);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), AF_INET); // family
        assert_eq!([b[2], b[3]], 80u16.to_be_bytes()); // port BE
        assert_eq!([b[4], b[5], b[6], b[7]], [127, 0, 0, 1]); // addr network order
    }

    #[test]
    fn numeric_v6_and_localhost() {
        let (fam, b, len) = fill_sockaddr(b"::1", 443, 0).unwrap();
        assert_eq!(fam, AF_INET6 as i32);
        assert_eq!(len, 28);
        assert_eq!([b[2], b[3]], 443u16.to_be_bytes());
        assert_eq!(b[8..24], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // localhost → v4 loopback when family unspecified
        let (fam2, b2, _) = fill_sockaddr(b"localhost", 22, 0).unwrap();
        assert_eq!(fam2, AF_INET as i32);
        assert_eq!([b2[4], b2[5], b2[6], b2[7]], [127, 0, 0, 1]);
        // unresolvable name without DNS
        assert!(fill_sockaddr(b"example.com", 80, 0).is_none());
    }

    #[test]
    fn hosts_file_name_and_alias_resolution() {
        let hosts = b"\
            # comment\n\
            192.0.2.5 testhost testalias\n\
            192.0.2.6 dual\n\
            2001:db8::6 dual\n\
            2001:db8::9 v6host\n";
        let (fam, b, len) = fill_sockaddr_from_hosts(hosts, b"testalias", 8080, 0).unwrap();
        assert_eq!(fam, AF_INET as i32);
        assert_eq!(len, 16);
        assert_eq!([b[2], b[3]], 8080u16.to_be_bytes());
        assert_eq!([b[4], b[5], b[6], b[7]], [192, 0, 2, 5]);

        let (fam, b, len) = fill_sockaddr_from_hosts(hosts, b"v6host", 53, AF_INET6 as i32).unwrap();
        assert_eq!(fam, AF_INET6 as i32);
        assert_eq!(len, 28);
        assert_eq!(b[8..24], [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        assert!(fill_sockaddr_from_hosts(hosts, b"v6host", 53, AF_INET as i32).is_none());

        let (fam, b, _) = fill_sockaddr_from_hosts(hosts, b"dual", 53, AF_INET6 as i32).unwrap();
        assert_eq!(fam, AF_INET6 as i32);
        assert_eq!(b[8..24], [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6]);
    }

    #[test]
    fn dns_answer_a_and_aaaa_resolution() {
        let a_answer = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // qname
            0x00, 0x01, 0x00, 0x01, // qtype/qclass
            0xc0, 0x0c, // compressed answer name
            0x00, 0x01, 0x00, 0x01, // A IN
            0x00, 0x00, 0x00, 0x3c, // ttl
            0x00, 0x04, 203, 0, 113, 7, // rdata
        ];
        let (fam, b, len) = fill_sockaddr_from_dns(&a_answer, 80, 0).unwrap();
        assert_eq!(fam, AF_INET as i32);
        assert_eq!(len, 16);
        assert_eq!([b[2], b[3]], 80u16.to_be_bytes());
        assert_eq!([b[4], b[5], b[6], b[7]], [203, 0, 113, 7]);

        let aaaa_answer = [
            0x12, 0x35, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x02, b'v', b'6', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00,
            0x00, 0x1c, 0x00, 0x01,
            0xc0, 0x0c,
            0x00, 0x1c, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3c,
            0x00, 0x10,
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
        ];
        let (fam, b, len) = fill_sockaddr_from_dns(&aaaa_answer, 443, AF_INET6 as i32).unwrap();
        assert_eq!(fam, AF_INET6 as i32);
        assert_eq!(len, 28);
        assert_eq!([b[2], b[3]], 443u16.to_be_bytes());
        assert_eq!(b[8..24], [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        assert!(fill_sockaddr_from_dns(&aaaa_answer, 443, AF_INET as i32).is_none());
    }
