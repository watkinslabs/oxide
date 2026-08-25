#![allow(dead_code)]

use super::*;

fn ep(ip: crate::addr::Ipv4Addr, port: u16) -> Endpoint {
    Endpoint {
        ip: crate::addr::IpAddr::V4(ip),
        port,
    }
}

fn lo_ip() -> crate::addr::IpAddr {
    crate::addr::IpAddr::V4(crate::addr::Ipv4Addr::LOOPBACK)
}


mod handshake;
mod urgent;
mod retransmit;
mod reset;
mod receive;
mod passive;

