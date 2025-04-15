use crate::protocols::dyn_protocols::Protocol;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

/// Implementation of IPv4 header.
///
#[derive(Clone, PartialEq, Debug)]
pub struct Ipv4Header {
    /// A flat vector of parsed bit values, size up to 480 bits as it's the max IPv4 header length
    data: Vec<f32>, // 480 = IHL max size
}

impl Default for Ipv4Header {
    /// Returns an `Ipv4Header` filled with 480 "-1"
    fn default() -> Self {
        Self {
            data: vec![-1.; 480],
        }
    }
}

impl Protocol for Ipv4Header {
    /// Constructs an `Ipv4Header` from a raw bytes IPv4 packet.
    ///
    /// If the input is a valid IPv4 packet, its fields are parsed bit by bit.
    /// If the packet is invalid or cannot be parsed, return Default.
    ///
    /// # Arguments
    /// * `packet` - Raw bytes representing an IPv4 packet.
    fn new(packet: &[u8]) -> Ipv4Header {
        if let Some(packet) = Ipv4Packet::new(packet) {
            let option = packet.get_options_raw();
            let mut data = Vec::with_capacity(480);
            let packet = packet.packet();
            data.extend((0..4).rev().map(|i| ((packet[0] >> (4 + i)) & 1) as f32));
            data.extend((0..4).rev().map(|i| ((packet[0] >> i) & 1) as f32));
            data.extend((0..6).rev().map(|i| ((packet[1] >> (2 + i)) & 1) as f32));
            data.extend((0..2).rev().map(|i| ((packet[1] >> i) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[2 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[4 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..3).rev().map(|i| ((packet[6] >> (5 + i)) & 1) as f32));
            data.extend((0..13).map(|i| {
                if i < 5 {
                    ((packet[6] >> (4 - i)) & 1) as f32
                } else {
                    ((packet[7] >> (7 - (i - 5))) & 1) as f32
                }
            }));
            data.extend((0..8).rev().map(|i| ((packet[8] >> i) & 1) as f32));
            data.extend((0..8).rev().map(|i| ((packet[9] >> i) & 1) as f32));
            data.extend((0..16).map(|i| ((packet[10 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..32).map(|i| ((packet[12 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend((0..32).map(|i| ((packet[16 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
            data.extend(get_options_bits(option));
            Ipv4Header { data }
        } else {
            eprintln!("Not an IPv4 packet, returnin default...");
            Ipv4Header::default()
        }
    }

    /// Returns a reference to the extracted data, or the default header if the extraction failed.
    fn get_data(&self) -> &Vec<f32> {
        &self.data
    }

    /// Returns the list of all field names of the protocols.
    ///
    /// Header names are suffixed with an index (e.g., `ipv4_ver_0`, `ipv4_ver_1`).
    fn get_headers_name() -> Vec<String> {
        let fields = vec![
            ("ipv4_ver", 4),
            ("ipv4_hl", 4),
            ("ipv4_tos", 8),
            ("ipv4_tl", 16),
            ("ipv4_id", 16),
            ("ipv4_rbit", 1),
            ("ipv4_dfbit", 1),
            ("ipv4_mfbit", 1),
            ("ipv4_foff", 13),
            ("ipv4_ttl", 8),
            ("ipv4_proto", 8),
            ("ipv4_cksum", 16),
            ("ipv4_src", 32),
            ("ipv4_dst", 32),
            ("ipv4_opt", 320),
        ];
        fields
            .iter()
            .flat_map(|(name, bits)| (0..*bits).map(move |i| format!("{}_{}", name, i)))
            .collect()
    }
}

impl Ipv4Header {
    /// Remove IPs to anonymized header.
    pub fn remove_ips(&mut self) {
        self.remove(96, 127);
        self.remove(128, 159);
    }

    /// Remove a given range.
    ///
    /// # Arguments
    /// * `start` - Starting bit index (inclusive).
    /// * `end` - Ending bit index (inclusive).
    pub fn remove(&mut self, start: usize, end: usize) {
        self.data[start..=end].fill(0.);
    }
}

/// Converts raw options bytes into a bit vector of 320 `f32`.
///
/// Fill with `-1.0` all the fields not present.
///
/// # Arguments
/// * `options` - Slice of bits from the option field of an IPv4 header.
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
