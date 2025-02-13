use pnet::packet::ipv4::Ipv4Packet;

#[derive(Clone, Debug)]
pub struct Ipv4Header {
    data: Vec<i8>, // 480 = IHL max size
}

impl Default for Ipv4Header {
    fn default() -> Self {
        Self {
            data: vec![-1; 480],
        }
    }
}

impl Ipv4Header {
    pub fn new(packet: &Ipv4Packet) -> Ipv4Header {
        let mut data = Vec::new();
        data.extend(
            (0..4)
                .rev()
                .map(|i| ((packet.get_version() >> i) & 1) as i8),
        );
        data.extend(
            (0..4)
                .rev()
                .map(|i| ((packet.get_header_length() >> i) & 1) as i8),
        );
        data.extend((0..6).rev().map(|i| ((packet.get_dscp() >> i) & 1) as i8));
        data.extend((0..2).rev().map(|i| ((packet.get_ecn() >> i) & 1) as i8));
        data.extend(
            (0..16)
                .rev()
                .map(|i| ((packet.get_total_length() >> i) & 1) as i8),
        );
        data.extend(
            (0..16)
                .rev()
                .map(|i| ((packet.get_identification() >> i) & 1) as i8),
        );
        data.extend((0..3).rev().map(|i| ((packet.get_flags() >> i) & 1) as i8));
        data.extend(
            (0..13)
                .rev()
                .map(|i| ((packet.get_fragment_offset() >> i) & 1) as i8),
        );
        data.extend((0..8).rev().map(|i| ((packet.get_ttl() >> i) & 1) as i8));
        data.extend(
            (0..8)
                .rev()
                .map(|i| ((packet.get_next_level_protocol().0 >> i) & 1) as i8),
        );
        data.extend(
            (0..16)
                .rev()
                .map(|i| ((packet.get_checksum() >> i) & 1) as i8),
        );
        data.extend(
            (0..32).map(|i| ((packet.get_source().octets()[i / 8] >> (7 - (i % 8))) & 1) as i8),
        );
        data.extend(
            (0..32)
                .map(|i| ((packet.get_destination().octets()[i / 8] >> (7 - (i % 8))) & 1) as i8),
        );
        data.extend(get_options_bits(packet.get_options_raw()));
        Ipv4Header { data }
    }
    pub fn get_data(&self) -> &Vec<i8> {
        &self.data
    }
    pub fn remove_ips(&mut self) {
        self.remove(96, 127);
        self.remove(128, 159);
    }
    pub fn remove(&mut self, start: usize, end: usize) {
        self.data[start..=end].fill(0);
    }
    pub fn get_headers() -> Vec<String> {
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
fn get_options_bits(options: &[u8]) -> Vec<i8> {
    let mut data = Vec::new();
    for option in options {
        data.push(*option as i8);
    }
    while data.len() < 320 {
        data.push(-1);
    }
    data
}
