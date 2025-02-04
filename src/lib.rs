pub mod protocols;
use crate::protocols::ipv4::Ipv4Header;
use pnet::packet::ipv4::Ipv4Packet;

use pnet::packet::ethernet::{EthernetPacket,EtherTypes};

pub struct Nprint{
    pub ipv4:Option<Ipv4Header>,
}

impl Nprint{
    pub fn new(packet:&[u8])-> Nprint{
        let ethernet = EthernetPacket::new(&packet).unwrap();
        if ethernet.get_ethertype() == EtherTypes::Ipv4{
            Nprint{
                ipv4:Some(Ipv4Header::new(Ipv4Packet::new(packet).unwrap()))
            }           
        } else {
            todo!()
        }
    }
}

pub fn hello_world() -> String {
    "hello_world".to_string()
}

