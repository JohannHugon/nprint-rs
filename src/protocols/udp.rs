use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[derive(Clone, Debug)]
pub struct UdpHeader {
    data: Vec<f32>,
}

impl Default for UdpHeader {
    fn default() -> Self {
        Self {
            data: vec![-1.; 64],
        }
    }
}

impl UdpHeader {
    pub fn new(packet: &UdpPacket) -> UdpHeader {
        let mut data = Vec::with_capacity(64);
        let packet = packet.packet();
        data.extend((0..16).map(|i| ((packet[i / 8] >> (7 - (i % 8))) & 1) as f32));
        data.extend((0..16).map(|i| ((packet[2 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
        data.extend((0..16).map(|i| ((packet[4 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
        data.extend((0..16).map(|i| ((packet[6 + (i / 8)] >> (7 - (i % 8))) & 1) as f32));
        UdpHeader { data }
    }
    pub fn get_data(&self) -> &Vec<f32> {
        &self.data
    }
    pub fn remove(&mut self, start: usize, end: usize) {
        self.data[start..=end].fill(0.);
    }
    pub fn get_headers() -> Vec<String> {
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
