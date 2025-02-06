use pnet::packet::tcp::TcpPacket;

#[derive(Clone,Debug)]
pub struct TcpHeader{
    data: Vec<i8>,
}

impl TcpHeader{
    pub fn new(packet: &TcpPacket) -> TcpHeader{
        let mut data = Vec::new();
        data.extend((0..16).rev().map(|i| ((packet.get_source() >> i) & 1) as i8));
        data.extend((0..16).rev().map(|i| ((packet.get_destination() >> i) & 1) as i8));
        data.extend((0..32).rev().map(|i| ((packet.get_sequence() >> i) & 1) as i8));
        data.extend((0..32).rev().map(|i| ((packet.get_acknowledgement() >> i) & 1) as i8));
        data.extend((0..4).rev().map(|i| ((packet.get_data_offset() >> i) & 1) as i8));
        data.extend((0..4).rev().map(|i| ((packet.get_reserved() >> i) & 1) as i8));
        data.extend((0..8).rev().map(|i| ((packet.get_flags() >> i) & 1) as i8));
        data.extend((0..16).rev().map(|i| ((packet.get_window() >> i) & 1) as i8));
        data.extend((0..16).rev().map(|i| ((packet.get_checksum() >> i) & 1) as i8));
        data.extend((0..16).rev().map(|i| ((packet.get_urgent_ptr() >> i) & 1) as i8));
        data.extend(get_options_bits(packet.get_options_raw()));
        TcpHeader{
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
fn get_options_bits(options: &[u8]) -> Vec<i8> {
    let mut data = Vec::new();
    for option in options {
        data.extend((0..8).rev().map(|i| ((option >> i) & 1) as i8));
    }
    while data.len() < 320 {
        data.push(-1);
    }
    data
}
