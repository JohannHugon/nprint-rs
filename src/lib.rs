pub mod protocols;
use crate::protocols::ipv4::Ipv4Header;
use crate::protocols::tcp::TcpHeader;
use crate::protocols::udp::UdpHeader;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[derive(Debug)]
pub struct Nprint {
    pub ipv4: Option<Ipv4Header>,
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
}

impl Nprint {
    pub fn new(packet: &[u8]) -> Nprint {
        let ethernet = EthernetPacket::new(packet).unwrap();

        let (ipv4, tcp, udp) = if ethernet.get_ethertype() == EtherTypes::Ipv4 {
            let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
            let ipv4 = Some(Ipv4Header::new(&ipv4_packet));
            let (tcp, udp) = match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    let tcp = Some(TcpHeader::new(
                        &TcpPacket::new(ipv4_packet.payload()).unwrap(),
                    ));
                    (tcp, None)
                }
                IpNextHeaderProtocols::Udp => {
                    let udp = Some(UdpHeader::new(
                        &UdpPacket::new(ipv4_packet.payload()).unwrap(),
                    ));
                    (None, udp)
                }
                _ => (None, None),
            };
            (ipv4, tcp, udp)
        } else {
            (None, None, None)
        };
        Nprint { ipv4, tcp, udp }
    }
    pub fn print(&self) -> Vec<i8> {
        let mut output = vec![];
        if let Some(ipv4) = &self.ipv4 {
            output.extend(ipv4.get_data());
        }
        if let Some(tcp) = &self.tcp {
            output.extend(tcp.get_data());
        }
        if let Some(udp) = &self.udp {
            output.extend(udp.get_data());
        }
        output
    }
}
