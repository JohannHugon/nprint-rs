use crate::protocols::dyn_protocols::Protocol;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct UdpHeader {
    data: Vec<f32>,
}

impl Default for UdpHeader {
    fn default() -> Self {
        Self {
            data: vec![-1.; 64],
        }
    }
}

impl Protocol for UdpHeader {
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
    fn get_data(&self) -> &Vec<f32> {
        &self.data
    }
    fn get_headers() -> Vec<String> {
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
    pub fn remove(&mut self, start: usize, end: usize) {
        self.data[start..=end].fill(0.);
    }
}

#[cfg(test)]
mod udp_header_tests {
    use super::*;

    #[test]
    fn test_udp_header_creation() {
        let raw_packet: Vec<u8> = vec![0xe1, 0x15, 0xe1, 0x15, 0x00, 0x34, 0x85, 0x00];
        let udp_header = UdpHeader::new(&raw_packet);
        //assert_eq!(udp_header.get_data().len(), 480, "Expected 480 bits in udpHeader data.");
        let udp_header_test = [
            1., 1., 1., 0., 0., 0., 0., 1., 0., 0., 0., 1., 0., 1., 0., 1., 1., 1., 1., 0., 0., 0.,
            0., 1., 0., 0., 0., 1., 0., 1., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 1.,
            0., 1., 0., 0., 1., 0., 0., 0., 0., 1., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0.,
        ];
        let data = udp_header.get_data();
        println!("{:?}", data);
        for i in 0..udp_header_test.len() {
            assert_eq!(
                data[i], udp_header_test[i],
                "udp header doesn't match expected on bit {}.",
                i
            );
        }
    }

    #[test]
    fn test_udp_header_get_headers() {
        let expected_headers = vec![
            "udp_sport_0",
            "udp_sport_1",
            "udp_sport_2",
            "udp_sport_3",
            "udp_sport_4",
            "udp_sport_5",
            "udp_sport_6",
            "udp_sport_7",
            "udp_sport_8",
            "udp_sport_9",
            "udp_sport_10",
            "udp_sport_11",
            "udp_sport_12",
            "udp_sport_13",
            "udp_sport_14",
            "udp_sport_15",
            "udp_dport_0",
            "udp_dport_1",
            "udp_dport_2",
            "udp_dport_3",
            "udp_dport_4",
            "udp_dport_5",
            "udp_dport_6",
            "udp_dport_7",
            "udp_dport_8",
            "udp_dport_9",
            "udp_dport_10",
            "udp_dport_11",
            "udp_dport_12",
            "udp_dport_13",
            "udp_dport_14",
            "udp_dport_15",
            "udp_len_0",
            "udp_len_1",
            "udp_len_2",
            "udp_len_3",
            "udp_len_4",
            "udp_len_5",
            "udp_len_6",
            "udp_len_7",
            "udp_len_8",
            "udp_len_9",
            "udp_len_10",
            "udp_len_11",
            "udp_len_12",
            "udp_len_13",
            "udp_len_14",
            "udp_len_15",
            "udp_cksum_0",
            "udp_cksum_1",
            "udp_cksum_2",
            "udp_cksum_3",
            "udp_cksum_4",
            "udp_cksum_5",
            "udp_cksum_6",
            "udp_cksum_7",
            "udp_cksum_8",
            "udp_cksum_9",
            "udp_cksum_10",
            "udp_cksum_11",
            "udp_cksum_12",
            "udp_cksum_13",
            "udp_cksum_14",
            "udp_cksum_15",
        ];

        let headers = UdpHeader::get_headers();
        for (i, expected) in expected_headers.iter().enumerate() {
            assert_eq!(
                headers[i], *expected,
                "Header at index {} does not match expected.",
                i
            );
        }
    }

    #[test]
    fn test_udp_header_bad_header() {
        let raw_packet: Vec<u8> = vec![0x45, 0x00, 0x00, 0x3c, 0xf5, 0x1b];
        let udp_header = UdpHeader::new(&raw_packet);
        assert_eq!(
            udp_header,
            UdpHeader::default(),
            "Expected data to be default."
        );
    }
}
