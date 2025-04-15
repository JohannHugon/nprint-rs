use crate::protocols::dyn_protocols::Protocol;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

/// Implementation of Udp header.
///
#[derive(Clone, PartialEq, Debug)]
pub struct UdpHeader {
    /// A flat vector of parsed bit values, size up to 64 bits as it's the max UDP header length
    data: Vec<f32>,
}

impl Default for UdpHeader {
    /// Returns an `UdpHeader` filled with 64 "-1"
    fn default() -> Self {
        Self {
            data: vec![-1.; 64],
        }
    }
}

impl Protocol for UdpHeader {
    /// Constructs an `UdpHeader` from a raw bytes UDP packet.
    ///
    /// If the input is a valid Udp packet, its fields are parsed bit by bit.
    /// If the packet is invalid or cannot be parsed, return Default.
    ///
    /// # Arguments
    /// * `packet` - Raw bytes representing an Udp packet.
    fn new(packet: &[u8]) -> UdpHeader {
        if let Some(packet) = UdpPacket::new(packet) {
            let mut data = Vec::with_capacity(64);
            let packet = packet.packet();
            data.extend((0..16).map(|i| ((packet[i / 8] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[2 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[4 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[6 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            UdpHeader { data }
        } else {
            eprintln!("Not an UDP packet, returnin default...");
            UdpHeader::default()
        }
    }

    /// Returns a reference to the extracted data, or the default header if the extraction failed.
    fn get_data(&self) -> &Vec<f32> {
        &self.data
    }

    /// Returns the name list of all field of the protocols.
    ///
    /// Header names are suffixed with an index (e.g., `udp_sport_0`, `udp_sport_1`).
    fn get_headers_name() -> Vec<String> {
        let fields = [
            ("udp_sport", 16),
            ("udp_dport", 16),
            ("udp_len", 16),
            ("udp_cksum", 16),
        ];

        fields
            .iter()
            .flat_map(|(name, bits)| (0..*bits).map(move |i| format!("{}_{}", name, i)))
            .collect()
    }
}

impl UdpHeader {
    /// Remove a given range.
    ///
    /// # Arguments
    /// * `start` - Starting bit index (inclusive).
    /// * `end` - Ending bit index (inclusive).
    pub fn remove(&mut self, start: usize, end: usize) {
        self.data[start..=end].fill(0.);
    }
}
