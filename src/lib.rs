pub mod protocols;
use crate::protocols::ipv4::Ipv4Header;
use crate::protocols::tcp::TcpHeader;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket,EtherTypes};

#[derive(Debug)]
pub struct Nprint{
    pub ipv4:Option<Ipv4Header>,
    pub tcp:Option<TcpHeader>,
}

impl Nprint{
    pub fn new(packet:&[u8])-> Nprint{
        let ethernet = EthernetPacket::new(&packet).unwrap();
        let mut ipv4 = None;
        let mut tcp = None;
        if ethernet.get_ethertype() == EtherTypes::Ipv4{
            let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
            ipv4 = Some(Ipv4Header::new(&ipv4_packet)); 
            if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp{
                tcp = Some(TcpHeader::new(&TcpPacket::new(ipv4_packet.payload()).unwrap()))
            } 
        } else {
            todo!()
        }

        Nprint{
            ipv4,
            tcp
        }           
    }
}
