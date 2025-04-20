//! nPrint is a standard data representation for network traffic, designed for direct use with machine learning algorithms, eliminating the need for feature engineering in various traffic analysis tasks. Developing a Rust implementation of nPrint will simplify the creation of network systems that leverage real-world ML deployments, rather than just training and deploying models offline.
pub mod protocols;
use crate::protocols::ipv4::Ipv4Header;
use crate::protocols::packet::PacketHeader;
use crate::protocols::tcp::TcpHeader;
use crate::protocols::udp::UdpHeader;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;

/// The `Nprint` structure stores a collection of parsed packet headers,
/// associated with a single network flow (e.g., a connection or tuple).
///
/// It maintains the list of protocols used for parsing and tracks the number of packets processed.
#[derive(Debug)]
pub struct Nprint {
    /// Vector that contains all the parsed headers for each packet.
    data: Vec<Headers>,
    /// Ordered list of Protocol selected for this Nprint.
    protocols: Vec<ProtocolType>,
    /// Number of packets processed.
    nb_pkt: usize,
}

/// Internal structure handling the extracted information of ONE single packet.
#[derive(Debug)]
pub(crate) struct Headers {
    /// Vector that contains ordered values extracted informations
    pub data: Vec<Box<dyn PacketHeader>>,
}

/// Enum that contains the current implemented type extractable
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolType {
    Ipv4,
    Tcp,
    Udp,
}

impl Nprint {
    /// Creates a new `Nprint` based the first packet of the connection and the vector of protocols.
    ///
    /// # Arguments
    ///
    /// * `packet` - A byte slice representing the raw packet data.
    /// * `protocols` - A vector of `ProtocolType` specifying the protocol stack to parse.
    ///
    /// # Returns
    ///
    /// A new `Nprint` instance containing the parsed headers of the packet.
    /// # Example
    ///
    /// ```
    /// use nprint_rs::ProtocolType;
    /// use nprint_rs::Nprint;
    ///
    /// let packet = vec![
    ///      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x08, 0x00, 0x45, 0x00,
    ///      0x00, 0x3c, 0xf5, 0x1b, 0x40, 0x00, 0x40, 0x06, 0x1b, 0x24, 0xc0, 0xa8, 0x2b, 0x25,
    ///      0xc6, 0x26, 0x78, 0x88, 0x97, 0xa4, 0x01, 0xbb, 0x96, 0x2e, 0x5e, 0x0b, 0x00, 0x00,
    ///      0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x25, 0xd4, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
    ///      0x04, 0x02, 0x08, 0x0a, 0xe3, 0xe2, 0x14, 0x23, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
    ///      0x03, 0x07];
    ///
    /// let nprint = Nprint::new(&packet, vec![ProtocolType::Ipv4, ProtocolType::Tcp,ProtocolType::Udp]);
    /// ```    
    pub fn new(packet: &[u8], protocols: Vec<ProtocolType>) -> Nprint {
        Nprint {
            data: vec![Headers::new(packet, &protocols)],
            protocols,
            nb_pkt: 1,
        }
    }

    /// Return all the nprint values in a vector of f32.
    ///
    /// This is useful for exporting structured packet data for ML models or analytics.
    ///
    /// # Returns
    ///
    /// A `Vec<f32>` containing all protocol data from each parsed packet in order.
    pub fn print(&self) -> Vec<f32> {
        let mut output = vec![];
        for header in &self.data {
            for proto in &header.data {
                output.extend((*proto).get_data());
            }
        }
        output
    }

    /// Adds a new packet to the `Nprint` structure, parsing it using the existing protocols.
    ///
    /// # Arguments
    ///
    /// * `packet` - A byte slice representing the new raw packet.
    pub fn add(&mut self, packet: &[u8]) {
        self.data.push(Headers::new(packet, &self.protocols));
        self.nb_pkt += 1;
    }

    /// Returns the number of packets.
    ///
    /// # Returns
    ///
    /// A `usize` representing the number of packets within the structure.
    pub fn count(&self) -> usize {
        self.nb_pkt
    }

    pub fn get_headers(&self) -> Vec<String> {
        let mut output = vec![];
        for proto in &self.protocols {
            match proto {
                ProtocolType::Ipv4 => {
                    output.extend(Ipv4Header::get_headers());
                }
                ProtocolType::Tcp => {
                    output.extend(TcpHeader::get_headers());
                }
                ProtocolType::Udp => {
                    output.extend(UdpHeader::get_headers());
                }
            }
        }
        output
    }

    /// Remove sensitive data from the captured header
    pub fn anonymize(&mut self) {
        for packet in self.data.iter_mut() {
            for header in packet.data.iter_mut() {
                header.anonymize();
            }
        }
    }
}

impl Headers {
    /// Creates a new `Headers` instance by parsing the given packet data
    /// according to the specified list of protocols.
    ///
    /// # Arguments
    ///
    /// * `packet` - A byte slice representing the raw packet.
    /// * `protocols` - A slice of `ProtocolType` enums specifying the protocol to parsed.
    ///
    /// # Returns
    ///
    /// A `Headers` struct containing the parsed protocol headers as specified.
    ///
    pub fn new(packet: &[u8], protocols: &[ProtocolType]) -> Headers {
        let mut data: Vec<Box<dyn PacketHeader>> = Vec::with_capacity(protocols.len());
        let mut ipv4 = None;
        let mut tcp = None;
        let mut udp = None;

        if let Some(ethernet) = EthernetPacket::new(packet) {
            let mut ethertype = ethernet.get_ethertype();
            let mut payload = ethernet.payload().to_vec();

            // Pop VLAN's Header
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
