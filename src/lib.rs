pub mod protocols;
use crate::protocols::ipv4::Ipv4Header;
use crate::protocols::tcp::TcpHeader;
use crate::protocols::udp::UdpHeader;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket,EtherTypes};

#[derive(Debug)]
pub struct Nprint{
    pub ipv4:Option<Ipv4Header>,
    pub tcp:Option<TcpHeader>,
    pub udp:Option<UdpHeader>,
}

impl Nprint{
    pub fn new(packet:&[u8])-> Nprint{
        let ethernet = EthernetPacket::new(&packet).unwrap();
        let mut ipv4 = None;
        let mut tcp = None;
        let mut udp = None;
        if ethernet.get_ethertype() == EtherTypes::Ipv4{
            let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
            ipv4 = Some(Ipv4Header::new(&ipv4_packet)); 
            println!("Proto {:?}",ipv4_packet.get_next_level_protocol());
            if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp{
                tcp = Some(TcpHeader::new(&TcpPacket::new(ipv4_packet.payload()).unwrap()));
            } else if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp{
                udp = Some(UdpHeader::new(&UdpPacket::new(ipv4_packet.payload()).unwrap()));
            } else {
                todo!()
            }
        } else {
            todo!()
        }

        Nprint{
            ipv4,
            tcp,
            udp
        }           
    }
    pub fn print(&self) -> Vec<i8>{
        let mut output = vec![];
        if let Some(ipv4) = &self.ipv4 {
            output.extend(ipv4.get_data());
        }
        if let Some(tcp)  = &self.tcp {
            output.extend(tcp.get_data());
        }
        if let Some(udp) = &self.udp {
            output.extend(udp.get_data());
        }    
        output
    }
}
