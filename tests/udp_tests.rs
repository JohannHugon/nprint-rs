#[cfg(test)]
mod udp_header_tests {
    use nprint_rs::protocols::udp::UdpHeader; 
    use pnet::packet::udp::UdpPacket;

    #[test]
    fn test_udp_header_creation() {
        let raw_packet: Vec<u8> = vec![ 0xe1, 0x15, 0xe1,0x15, 0x00,0x34, 0x85,0x00];
        let udp_packet = UdpPacket::new(&raw_packet).unwrap();
        let udp_header = UdpHeader::new(&udp_packet);
        //assert_eq!(udp_header.get_data().len(), 480, "Expected 480 bits in udpHeader data.");
        let udp_header_test= [1,1,1,0,0,0,0,1,0,0,0,1,0,1,0,1,1,1,1,0,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,0,0,0,0,0,0,0];
        let data = udp_header.get_data();
        println!("{:?}",data);
        for i in 0..udp_header_test.len(){
            assert_eq!(data[i], udp_header_test[i], "udp header doesn't match expected on bit {}.",i);
        }
    }

    #[test]
    fn test_udp_header_get_headers() {
        let expected_headers = vec!["udp_sport_0",
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
        "udp_cksum_15"]; 

        let headers = UdpHeader::get_headers();
        for (i, expected) in expected_headers.iter().enumerate() {
            assert_eq!(headers[i], *expected, "Header at index {} does not match expected.", i);
        }
    }
}

