// Wiring between the mandatory-access-control module and sockets.
//
// The module below `sched` answers the label questions and the boundary above
// stores nothing; this file is the only place the two meet, because it is the
// lowest crate that can see both. Nothing here decides policy — every answer
// comes from the module, and every stored id lives on the socket or connection
// that recorded it.

use syscall::errno::Errno;

fn operation_permission(operation: security::network::Operation) -> &'static str {
    use security::network::Operation::*;
    match operation {
        Create | SocketPair => "create",
        Bind => "bind",
        Connect => "connect",
        Listen => "listen",
        Accept => "accept",
        Send => "write",
        Receive => "read",
        Packet => "sendto",
        Shutdown => "shutdown",
        NameQuery => "getattr",
        SetOption => "setopt",
        GetOption => "getopt",
        Ioctl => "ioctl",
        NetlinkSend => "sendto",
        PeerConnect => "connectto",
        PeerSend => "sendto",
        NameBind => "name_bind",
        NameConnect => "name_connect",
        NodeBind => "node_bind",
    }
}

/// The SELinux socket hook consumes the socket SID retained by the network
/// object. Metadata-only admissions deliberately carry `NO_LABEL`; those
/// callers are completed by the socket-aware path before they reach policy.
fn socket_hook(context: security::network::Context) -> security::network::Verdict {
    if context.target_sid == security::network::NO_LABEL {
        return security::network::Verdict::Allow;
    }
    let Some(class) = selinux::uapi::classmap::class_by_name(context.target_class) else {
        return security::network::Verdict::Allow;
    };
    let permission_name = if matches!(context.operation, security::network::Operation::NetlinkSend) {
        netlink_permission(context.protocol as u16, context.message_type)
    } else { operation_permission(context.operation) };
    let Some(permission) = selinux::uapi::classmap::perm_bit(class, permission_name) else {
        return security::network::Verdict::Allow;
    };
    let result = if matches!(context.operation, security::network::Operation::NetlinkSend)
        && selinux_runtime::network::netlink_xperm()
    {
        selinux_runtime::check::has_xperm(selinux_runtime::task::current_sid(),
            context.target_sid, class, permission,
            selinux::avtab::AVTAB_XPERMS_NLMSG,
            (context.message_type >> 8) as u8, context.message_type as u8)
    } else {
        selinux_runtime::check::has_perm(selinux_runtime::task::current_sid(),
            context.target_sid, class, permission)
    };
    match result {
        Ok(()) => security::network::Verdict::Allow,
        Err(_) => security::network::Verdict::Deny,
    }
}

/// Linux's route netlink table classifies each RTM request, rather than using
/// the operation's numeric parity. Keep this table at the SELinux boundary so
/// netlink only supplies the wire message type.
fn netlink_permission(protocol: u16, message_type: u16) -> &'static str {
    if protocol != 0 { return "sendto"; }
    // The common RTM table is kept explicit here; unknown route extensions
    // remain readable until their policy table is taught the new message.
    match message_type {
        16 | 17 | 19 | 20 | 21 | 23 | 24 | 25 | 28 | 29 | 32 | 33 |
        56 | 57 | 60 | 61 | 88 | 89 | 120 | 121 => return "nlmsg_write",
        18 | 22 | 26 | 30 | 34 | 58 | 62 | 90 | 122 => return "nlmsg_read",
        _ => {}
    }
    match message_type {
        16 | 17 | 19 | 20 | 21 | 22 | 24 | 25 | 27 | 28 | 30 | 31 |
        32 | 33 | 35 | 36 | 38 | 39 | 40 | 41 | 43 | 44 | 46 | 47 |
        48 | 49 | 51 | 52 | 54 | 55 | 57 | 58 | 60 | 61 | 63 | 64 |
        66 | 67 | 69 | 70 | 72 | 73 | 75 | 76 | 78 | 79 | 80 | 81 |
        83 | 84 | 86 | 87 | 88 | 89 | 91 | 92 | 94 | 95 | 97 | 98 |
        100 | 101 | 103 | 104 | 106 | 107 | 109 | 110 | 112 | 113 |
        115 | 116 | 118 | 119 | 121 | 122 | 124 | 125 | 127 | 128 |
        130 | 131 | 133 | 134 | 136 | 137 | 139 | 140 | 142 | 143 |
        145 | 146 | 148 | 149 | 151 | 152 | 154 | 155 | 157 | 158 |
        160 | 161 | 163 | 164 | 166 | 167 | 169 | 170 | 172 | 173 |
        175 | 176 | 178 | 179 | 181 | 182 | 184 | 185 | 187 | 188 |
        190 | 191 | 193 | 194 | 196 | 197 | 199 | 200 | 202 | 203 |
        205 | 206 | 208 | 209 | 211 | 212 | 214 | 215 | 217 | 218 |
        220 | 221 | 223 | 224 | 226 | 227 | 229 | 230 | 232 | 233 |
        235 | 236 | 238 | 239 | 241 | 242 | 244 | 245 | 247 | 248 |
        250 | 251 | 253 | 254 | 256 | 257 | 259 | 260 | 262 | 263 |
        265 | 266 | 268 | 269 | 271 | 272 | 274 | 275 | 277 | 278 |
        280 | 281 | 283 | 284 | 286 | 287 | 289 | 290 | 292 | 293 |
        295 | 296 | 298 | 299 | 301 | 302 | 304 | 305 | 307 | 308 |
        310 | 311 | 313 | 314 | 316 | 317 | 319 | 320 | 322 | 323 |
        325 | 326 | 328 | 329 | 331 | 332 | 334 | 335 | 337 | 338 |
        340 | 341 | 343 | 344 | 346 | 347 | 349 | 350 | 352 | 353 |
        355 | 356 | 358 | 359 | 361 | 362 | 364 | 365 | 367 | 368 |
        370 | 371 | 373 | 374 | 376 | 377 | 379 | 380 | 382 | 383 |
        385 | 386 | 388 | 389 | 391 | 392 | 394 | 395 | 397 | 398 |
        400 | 401 | 403 | 404 | 406 | 407 | 409 | 410 | 412 | 413 |
        415 | 416 | 418 | 419 | 421 | 422 | 424 | 425 | 427 | 428 |
        430 | 431 | 433 | 434 | 436 | 437 | 439 | 440 | 442 | 443 |
        445 | 446 | 448 | 449 | 451 | 452 | 454 | 455 | 457 | 458 |
        460 | 461 | 463 | 464 | 466 | 467 | 469 | 470 | 472 | 473 |
        475 | 476 | 478 | 479 | 481 | 482 | 484 | 485 | 487 | 488 |
        490 | 491 | 493 | 494 | 496 | 497 | 499 | 500 | 502 | 503 |
        505 | 506 | 508 | 509 | 511 | 512 | 514 | 515 | 517 | 518 |
        520 | 521 | 523 | 524 | 526 | 527 | 529 | 530 | 532 | 533 |
        535 | 536 | 538 | 539 | 541 | 542 | 544 | 545 | 547 | 548 |
        550 | 551 | 553 | 554 | 556 | 557 | 559 | 560 | 562 | 563 |
        565 | 566 | 568 | 569 | 571 | 572 | 574 | 575 | 577 | 578 |
        580 | 581 | 583 | 584 | 586 | 587 | 589 | 590 | 592 | 593 |
        595 | 596 | 598 | 599 | 601 | 602 | 604 | 605 | 607 | 608 |
        610 | 611 | 613 | 614 | 616 | 617 | 619 | 620 | 622 | 623 |
        625 | 626 | 628 | 629 | 631 | 632 | 634 | 635 | 637 | 638 |
        640 | 641 | 643 | 644 | 646 | 647 | 649 | 650 | 652 | 653 |
        655 | 656 | 658 | 659 | 661 | 662 | 664 | 665 | 667 | 668 |
        670 | 671 | 673 | 674 | 676 | 677 | 679 | 680 | 682 | 683 |
        685 | 686 | 688 | 689 | 691 | 692 | 694 | 695 | 697 | 698 |
        700 | 701 | 703 | 704 | 706 | 707 | 709 | 710 | 712 | 713 |
        715 | 716 | 718 | 719 | 721 | 722 | 724 | 725 | 727 | 728 |
        730 | 731 | 733 | 734 | 736 | 737 | 739 | 740 | 742 | 743 |
        745 | 746 | 748 | 749 | 751 | 752 | 754 | 755 | 757 | 758 |
        760 | 761 | 763 | 764 | 766 | 767 | 769 | 770 | 772 | 773 |
        775 | 776 | 778 | 779 | 781 | 782 | 784 | 785 | 787 | 788 |
        790 | 791 | 793 | 794 | 796 | 797 | 799 | 800 | 802 | 803 |
        805 | 806 | 808 | 809 | 811 | 812 | 814 | 815 | 817 | 818 |
        820 | 821 | 823 | 824 | 826 | 827 | 829 | 830 | 832 | 833 |
        835 | 836 | 838 | 839 | 841 | 842 | 844 | 845 | 847 | 848 |
        850 | 851 | 853 | 854 | 856 | 857 | 859 | 860 | 862 | 863 |
        865 | 866 | 868 | 869 | 871 | 872 | 874 | 875 | 877 | 878 |
        880 | 881 | 883 | 884 | 886 | 887 | 889 | 890 | 892 | 893 |
        895 | 896 | 898 | 899 | 901 | 902 | 904 | 905 | 907 | 908 |
        910 | 911 | 913 | 914 | 916 | 917 | 919 | 920 | 922 | 923 |
        925 | 926 | 928 | 929 | 931 | 932 | 934 | 935 | 937 | 938 |
        940 | 941 | 943 | 944 | 946 | 947 | 949 | 950 | 952 | 953 |
        955 | 956 | 958 | 959 | 961 | 962 | 964 | 965 | 967 | 968 |
        970 | 971 | 973 | 974 | 976 | 977 | 979 | 980 | 982 | 983 |
        985 | 986 | 988 | 989 | 991 | 992 | 994 | 995 | 997 | 998 |
        1000 | 1001 | 1003 | 1004 | 1006 | 1007 | 1009 | 1010 | 1012 | 1013 |
        1015 | 1016 | 1018 | 1019 | 1021 | 1022 | 1024 | 1025 | 1027 | 1028 |
        1030 | 1031 | 1033 | 1034 | 1036 | 1037 | 1039 | 1040 | 1042 | 1043 |
        1045 | 1046 | 1048 | 1049 | 1051 | 1052 | 1054 | 1055 | 1057 | 1058 |
        1060 | 1061 | 1063 | 1064 | 1066 | 1067 | 1069 | 1070 | 1072 | 1073 |
        1075 | 1076 | 1078 | 1079 | 1081 | 1082 | 1084 | 1085 | 1086 | 1087 => "nlmsg_write",
        16..=1087 => "nlmsg_read",
        _ => "sendto",
    }
}

fn create(class: security::network::SocketClass) -> u32 {
    let name = socket_class_name(class, selinux_runtime::network::extended_socket_class());
    selinux_runtime::network::create_sid(name)
}

fn socket_class_name(class: security::network::SocketClass, extended: bool) -> &'static str {
    use security::network::SocketClass;
    match class {
        SocketClass::Tcp => "tcp_socket",
        SocketClass::Udp => "udp_socket",
        SocketClass::RawIp => "rawip_socket",
        SocketClass::Icmp if extended => "icmp_socket",
        SocketClass::Icmp => "rawip_socket",
        SocketClass::Packet => "packet_socket",
        SocketClass::UnixStream => "unix_stream_socket",
        SocketClass::UnixDgram => "unix_dgram_socket",
        SocketClass::Netlink => "netlink_socket",
    }
}

fn netlink_class_name(protocol: u16) -> &'static str {
    use netlink_protocols::*;
    match protocol {
        NETLINK_ROUTE => "netlink_route_socket",
        NETLINK_SOCK_DIAG => "netlink_tcpdiag_socket",
        NETLINK_NFLOG => "netlink_nflog_socket",
        NETLINK_XFRM => "netlink_xfrm_socket",
        NETLINK_SELINUX => "netlink_selinux_socket",
        NETLINK_ISCSI => "netlink_iscsi_socket",
        NETLINK_AUDIT => "netlink_audit_socket",
        NETLINK_FIB_LOOKUP => "netlink_fib_lookup_socket",
        NETLINK_CONNECTOR => "netlink_connector_socket",
        NETLINK_NETFILTER => "netlink_netfilter_socket",
        NETLINK_DNRTMSG => "netlink_dnrt_socket",
        NETLINK_KOBJECT_UEVENT => "netlink_kobject_uevent_socket",
        NETLINK_GENERIC => "netlink_generic_socket",
        NETLINK_SCSITRANSPORT => "netlink_scsitransport_socket",
        NETLINK_RDMA => "netlink_rdma_socket",
        NETLINK_CRYPTO => "netlink_crypto_socket",
        _ => "netlink_socket",
    }
}

fn create_netlink(protocol: u16) -> u32 {
    selinux_runtime::network::create_sid(netlink_class_name(protocol))
}

mod netlink_protocols {
    pub const NETLINK_ROUTE: u16 = 0; pub const NETLINK_SOCK_DIAG: u16 = 4;
    pub const NETLINK_NFLOG: u16 = 5; pub const NETLINK_XFRM: u16 = 6;
    pub const NETLINK_SELINUX: u16 = 7; pub const NETLINK_ISCSI: u16 = 8;
    pub const NETLINK_AUDIT: u16 = 9; pub const NETLINK_FIB_LOOKUP: u16 = 10;
    pub const NETLINK_CONNECTOR: u16 = 11; pub const NETLINK_NETFILTER: u16 = 12;
    pub const NETLINK_DNRTMSG: u16 = 14; pub const NETLINK_KOBJECT_UEVENT: u16 = 15;
    pub const NETLINK_GENERIC: u16 = 16; pub const NETLINK_SCSITRANSPORT: u16 = 18;
    pub const NETLINK_RDMA: u16 = 20; pub const NETLINK_CRYPTO: u16 = 21;
}

fn context(label: u32) -> Result<alloc::vec::Vec<u8>, Errno> {
    selinux_runtime::network::context(label).map_err(|error| match error {
        selinux_runtime::network::ContextError::NoMemory => Errno::Enomem,
        selinux_runtime::network::ContextError::InvalidLabel => Errno::Einval,
    })
}

/// Publish the security module as the one that labels sockets. # C: O(1)
///
/// Called once at boot, after the security server is installed and before the
/// first socket is created. A socket created before this runs carries no label
/// and reports none for its peers, so this must not be deferred past the first
/// socket the kernel opens.
///
/// Returns whether this call installed it; a second call is refused rather than
/// replacing the first, so two callers cannot leave sockets labelled from one
/// module and rendered by another.
pub fn init() -> bool {
    let labels = security::network::install_socket_label(security::network::SocketLabelOps {
        create,
        create_netlink,
        unlabeled: selinux_runtime::network::unlabeled(),
        context,
        server_end: selinux_runtime::network::server_end_sid,
    });
    if !labels { return false; }
    use security::network::Operation;
    for operation in [Operation::Create, Operation::Bind, Operation::Connect,
        Operation::Listen, Operation::Accept, Operation::Send, Operation::Receive,
        Operation::Shutdown, Operation::NameQuery, Operation::SocketPair,
        Operation::SetOption, Operation::GetOption, Operation::Ioctl, Operation::Packet,
        Operation::NetlinkSend, Operation::PeerConnect, Operation::PeerSend,
        Operation::NameBind, Operation::NameConnect, Operation::NodeBind] {
        let _ = security::network::install_global(operation, socket_hook);
    }
    true
}

/// Resolve the security context used by an nft SECMARK object through the
/// one installed SELinux server. # C: O(categories)
pub fn secmark_sid(context: &str) -> Option<u32> {
    selinux_runtime::network::sid_from_context(context)
}

/// Resolve a transport port's policy object context at the SELinux boundary.
pub fn port_sid(protocol: u8, port: u16) -> u32 {
    selinux_runtime::network::port_sid(protocol, port)
}

pub fn node_sid_v4(addr: u32) -> u32 {
    selinux_runtime::network::node_sid_v4(addr)
}

pub fn node_sid_v6(addr: [u32; 4]) -> u32 {
    selinux_runtime::network::node_sid_v6(addr)
}

#[cfg(test)]
mod tests {
    use super::{operation_permission, socket_class_name};
    use security::network::{Operation, SocketClass};

    #[test]
    fn socket_messages_use_linux_read_write_permissions() {
        assert_eq!(operation_permission(Operation::Send), "write");
        assert_eq!(operation_permission(Operation::Receive), "read");
    }

    #[test]
    fn every_constructor_class_maps_to_its_policy_class() {
        assert_eq!(socket_class_name(SocketClass::Tcp, false), "tcp_socket");
        assert_eq!(socket_class_name(SocketClass::Udp, false), "udp_socket");
        assert_eq!(socket_class_name(SocketClass::RawIp, false), "rawip_socket");
        assert_eq!(socket_class_name(SocketClass::Packet, false), "packet_socket");
        assert_eq!(socket_class_name(SocketClass::UnixStream, false), "unix_stream_socket");
        assert_eq!(socket_class_name(SocketClass::UnixDgram, false), "unix_dgram_socket");
        assert_eq!(socket_class_name(SocketClass::Icmp, false), "rawip_socket");
        assert_eq!(socket_class_name(SocketClass::Icmp, true), "icmp_socket");
    }
}
