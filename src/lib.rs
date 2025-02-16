pub mod protocols;
use crate::protocols::ipv4::Ipv4Header;
use crate::protocols::tcp::TcpHeader;
use crate::protocols::udp::UdpHeader;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;

#[derive(Debug)]
pub struct Nprint {
    pub data: Vec<Headers>,
    protocols: Vec<Protocol>,
}

#[derive(Debug)]
pub struct Headers {
    pub ipv4: Option<Ipv4Header>,
    pub tcp: Option<TcpHeader>,
    pub udp: Option<UdpHeader>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    Ipv4,
    Tcp,
    Udp,
}

impl Nprint {
    pub fn new(packet: &[u8], protocols: Vec<Protocol>) -> Nprint {
        Nprint {
            data: vec![Headers::new(packet, &protocols)],
            protocols,
        }
    }

    pub fn print(&self) -> Vec<f32> {
        let mut output = vec![];
        for header in &self.data {
            if let Some(ipv4) = &header.ipv4 {
                output.extend(ipv4.get_data());
            }
            if let Some(tcp) = &header.tcp {
                output.extend(tcp.get_data());
            }
            if let Some(udp) = &header.udp {
                output.extend(udp.get_data());
            }
        }
        output
    }

    pub fn add(&mut self, packet: &[u8]) {
        self.data.push(Headers::new(packet, &self.protocols));
    }
}

impl Headers {
    pub fn new(packet: &[u8], protocols: &Vec<Protocol>) -> Headers {
        let ethernet = EthernetPacket::new(packet).unwrap();
        let mut ethertype = ethernet.get_ethertype();
        let mut payload = ethernet.payload().to_vec();
        if ethertype == EtherTypes::Vlan {
            let vlan_packet = VlanPacket::new(ethernet.payload()).unwrap();
            ethertype = vlan_packet.get_ethertype();
            payload = vlan_packet.payload().to_vec();
        }
        let (ipv4, tcp, udp) = if ethertype == EtherTypes::Ipv4 {
            let ipv4_packet = Ipv4Packet::new(&payload).unwrap();
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
        Headers { 
            ipv4:if protocols.contains(&Protocol::Ipv4) { if ipv4.is_some() {ipv4} else {Some(Ipv4Header::default())}} else {None},
            tcp:if protocols.contains(&Protocol::Tcp) { if tcp.is_some() {tcp} else {Some(TcpHeader::default())}} else {None},
            udp:if protocols.contains(&Protocol::Udp) { if udp.is_some() {udp} else {Some(UdpHeader::default())}} else {None},
        }
    }
}
