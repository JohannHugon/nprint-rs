use crate::protocols::dyn_protocols::Protocol;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

/// Implementation of IPv4 header dissector.
///
#[derive(Clone, PartialEq, Debug)]
pub struct TcpHeader {
    /// A flat vector of parsed bit values, size up to 480 bits as it's the max TCP header length
    data: Vec<f32>,
}

impl Default for TcpHeader {
    /// Returns an `TcpHeader` filled with 480 "-1"
    fn default() -> Self {
        Self {
            data: vec![-1.; 480],
        }
    }
}

impl Protocol for TcpHeader {
    /// Constructs an `TcpHeader` from a raw bytes Tcp packet.
    ///
    /// If the input is a valid Tcp packet, its fields are parsed bit by bit.
    /// If the packet is invalid or cannot be parsed, return Default.
    ///
    /// # Arguments
    /// * `packet` - Raw bytes representing an Tcp packet.
    fn new(packet: &[u8]) -> TcpHeader {
        if let Some(packet) = TcpPacket::new(packet) {
            let option = packet.get_options_raw();
            let mut data = Vec::with_capacity(480);
            let packet = packet.packet();
            data.extend((0..16).map(|i| ((packet[i / 8] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[2 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..32).map(|i| ((packet[4 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..32).map(|i| ((packet[8 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..4).rev().map(|i| ((packet[12] >> (4 + i)) & 1) as f32));
            data.extend((0..4).rev().map(|i| ((packet[12] >> i) & 1) as f32));
            data.extend((0..8).rev().map(|i| ((packet[13] >> i) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[14 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[16 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[18 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend(get_options_bits(option));
            TcpHeader { data }
        } else {
            eprintln!("Not an TCP packet, returnin default...");
            TcpHeader::default()
        }
    }

    /// Return a reference of the extracted data
    fn get_data(&self) -> &Vec<f32> {
        &self.data
    }

    /// Returns the name list of all field of the protocols.
    /// 
    /// Header names are suffixed with an index (e.g., `tcp_sprt_0`, `tcp_sprt_1`).
    fn get_headers() -> Vec<String> {
        let fields = vec![
            ("tcp_sprt", 16),
            ("tcp_dprt", 16),
            ("tcp_seq", 32),
            ("tcp_ackn", 32),
            ("tcp_doff", 4),
            ("tcp_res", 3),
            ("tcp_ns", 1),
            ("tcp_cwr", 1),
            ("tcp_ece", 1),
            ("tcp_urg", 1),
            ("tcp_ackf", 1),
            ("tcp_psh", 1),
            ("tcp_rst", 1),
            ("tcp_syn", 1),
            ("tcp_fin", 1),
            ("tcp_wsize", 16),
            ("tcp_cksum", 16),
            ("tcp_urp", 16),
            ("tcp_opt", 320),
        ];

        fields
            .iter()
            .flat_map(|(name, bits)| (0..*bits).map(move |i| format!("{}_{}", name, i)))
            .collect()
    }
}

impl TcpHeader {
    /// Remove a given range.
    ///
    /// # Arguments
    /// * `start` - Starting bit index (inclusive).
    /// * `end` - Ending bit index (inclusive).
    pub fn remove(&mut self, start: usize, end: usize) {
        self.data[start..=end].fill(0.);
    }
}

/// Converts raw options bytes into a bit vector of `f32`.
///
/// Fill with `-1.0` all the fields not present.
///
/// # Arguments
/// * `options` - Slice of bits from the option field of an Tcp header.
///
/// # Returns
/// A 320-length vector of `f32` representing option bits.
fn get_options_bits(options: &[u8]) -> Vec<f32> {
    let mut data = Vec::new();
    for option in options {
        data.extend((0..8).rev().map(|i| ((option >> i) & 1) as f32));
    }
    while data.len() < 320 {
        data.push(-1.);
    }
    data
}
