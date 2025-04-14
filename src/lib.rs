pub mod protocols;
use crate::protocols::dyn_protocols::Protocol;
use crate::protocols::ipv4::Ipv4Header;
use crate::protocols::tcp::TcpHeader;
use crate::protocols::udp::UdpHeader;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;

#[derive(Debug)]
pub struct Nprint {
    pub data: Vec<Headers>,
    protocols: Vec<ProtocolType>,
    nb_pkt: usize,
}

#[derive(Debug)]
pub struct Headers {
    pub data: Vec<Box<dyn Protocol>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolType {
    Ipv4,
    Tcp,
    Udp,
}

impl Nprint {
    pub fn new(packet: &[u8], protocols: Vec<ProtocolType>) -> Nprint {
        Nprint {
            data: vec![Headers::new(packet, &protocols)],
            protocols,
            nb_pkt: 1,
        }
    }

    pub fn print(&self) -> Vec<f32> {
        let mut output = vec![];
        for header in &self.data {
            for proto in &header.data {
                output.extend((*proto).get_data());
            }
        }
        output
    }

    pub fn add(&mut self, packet: &[u8]) {
        self.data.push(Headers::new(packet, &self.protocols));
        self.nb_pkt += 1;
    }

    pub fn count(&self) -> usize {
        self.nb_pkt
    }
}

impl Headers {
    pub fn new(packet: &[u8], protocols: &[ProtocolType]) -> Headers {
        let mut data: Vec<Box<dyn Protocol>> = Vec::with_capacity(protocols.len());
        let mut ipv4 = None;
        let mut tcp = None;
        let mut udp = None;

        if let Some(ethernet) = EthernetPacket::new(packet) {
            let mut ethertype = ethernet.get_ethertype();
            let mut payload = ethernet.payload().to_vec();
            if ethertype == EtherTypes::Vlan {
                if let Some(vlan_packet) = VlanPacket::new(&payload) {
                    ethertype = vlan_packet.get_ethertype();
                    payload = vlan_packet.payload().to_vec();
                }
            }
            if ethertype == EtherTypes::Ipv4 {
                if let Some(ipv4_packet) = Ipv4Packet::new(&payload) {
                    ipv4 = Some(Ipv4Header::new(&payload));

                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            tcp = Some(TcpHeader::new(ipv4_packet.payload()));
                        }
                        IpNextHeaderProtocols::Udp => {
                            udp = Some(UdpHeader::new(ipv4_packet.payload()));
                        }
                        _ => {}
                    }
                }
            }
        } else {
            eprintln!("Not an EthernetPacket packet, returning default...");
        }

        for proto in protocols {
            match proto {
                ProtocolType::Ipv4 => {
                    data.push(Box::new(ipv4.clone().unwrap_or_else(Ipv4Header::default)));
                }
                ProtocolType::Tcp => {
                    data.push(Box::new(tcp.clone().unwrap_or_else(TcpHeader::default)));
                }
                ProtocolType::Udp => {
                    data.push(Box::new(udp.clone().unwrap_or_else(UdpHeader::default)));
                }
            }
        }
        Headers { data }
    }
}
