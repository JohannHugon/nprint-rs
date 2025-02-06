use pnet::packet::udp::UdpPacket;

#[derive(Clone,Debug)]
pub struct UdpHeader{
    data: Vec<i8>,
}

impl UdpHeader{
    pub fn new(packet: &UdpPacket) -> UdpHeader{
        let mut data = Vec::new();
        data.extend((0..16).rev().map(|i| ((packet.get_source() >> i) & 1) as i8));
        data.extend((0..16).rev().map(|i| ((packet.get_destination() >> i) & 1) as i8));
        data.extend((0..16).rev().map(|i| ((packet.get_length() >> i) & 1) as i8));
        data.extend((0..16).rev().map(|i| ((packet.get_checksum() >> i) & 1) as i8));
        UdpHeader{
            data,
        }
    }
    pub fn get_data(&self)->&Vec<i8>{
        &self.data
    }
    pub fn remove(&mut self,start: usize,end:usize){
        self.data[start..=end].fill(0);
    }
    pub fn get_headers() -> Vec<String> {
        let fields = vec![
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

