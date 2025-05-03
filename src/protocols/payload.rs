use crate::protocols::packet::PacketHeader;

/// Implementation of Payload header.
///
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct PayloadHeader {
    /// A flat vector of parsed bit values, size up to 1514*8 bits as it's the max Payload length
    data: Vec<f32>, // 1514*8 = MTU
}

impl Default for PayloadHeader {
    /// Returns an `PayloadHeader` filled with 1514 "-1"
    fn default() -> Self {
        Self {
            data: vec![-1.; 1514 * 8],
        }
    }
}

impl PacketHeader for PayloadHeader {
    /// Constructs an `PayloadHeader` from a raw bytes Payload packet.
    ///
    /// If the input as a valid size, it willbe parsed bit by bit.
    /// If the packet too long invalid, return Default.
    ///
    /// # Arguments
    /// * `packet` - Raw bytes representing an Payload packet.
    fn new(packet: &[u8]) -> PayloadHeader {
        let len = packet.len();
        if len < 1514 {
            let mut data = Vec::with_capacity(1514 * 8);
            data.extend((0..len * 8).map(|i| (((packet[i / 8] >> (7 - (i % 8))) & 1) as f32)));
            data.resize(1514 * 8, -1.);
            PayloadHeader { data }
        } else {
            eprintln!("Size superior of MTU, returning default...");
            PayloadHeader::default()
        }
    }

    /// Returns a reference to the extracted data, or the default header if the extraction failed.
    fn get_data(&self) -> &Vec<f32> {
        &self.data
    }

    /// Returns the list of all field names of the protocols.
    ///
    /// Header names are suffixed with an index (e.g., `Payload_bit_0`, `Payload_bit_1`).
    fn get_headers() -> Vec<String> {
        let fields = [("Payload_bit", 1514 * 8)];
        fields
            .iter()
            .flat_map(|(name, bits)| (0..*bits).map(move |i| format!("{}_{}", name, i)))
            .collect()
    }

    /// Nothing to remove.
    fn anonymize(&mut self) {}
}

impl PayloadHeader {}

#[cfg(test)]
mod payload_header_tests {
    use super::*;

    #[test]
    fn test_payload_header_creation() {
        let raw_packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x3c, 0xf5, 0x1b, 0x40, 0x00, 0x40, 0x06, 0x1b, 0x24, 0xc0, 0xa8,
            0x2b, 0x25, 0xc6, 0x26, 0x78, 0x88, 0x97, 0xa4, 0x01, 0xbb, 0x96, 0x2e, 0x5e, 0x0b,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x25, 0xd4, 0x00, 0x00, 0x02, 0x04,
            0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xe3, 0xe2, 0x14, 0x23, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x03, 0x03, 0x07,
        ];
        let payload_header = PayloadHeader::new(&raw_packet);
        let mut payload_header_test = vec![
            0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0,
            1.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0,
            0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0,
            1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0,
            0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0,
            0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0,
            1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 1.0,
            1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0,
            1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0,
            0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0,
            0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0,
            1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 0.0, 0.0,
            0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0,
            0.0, 1.0, 1.0, 1.0,
        ];
        payload_header_test.resize(1514 * 8, -1.);
        let data = payload_header.get_data();
        print!("{:?}", data);
        for i in 0..payload_header_test.len() {
            assert_eq!(
                data[i], payload_header_test[i],
                "Payload header doesn't match expected on bit {}.",
                i
            );
        }
    }

    #[test]
    fn test_payload_header_get_headers() {
        let expected_headers: Vec<String> = {
            let fields = [("Payload_bit", 1514 * 8)];
            fields
                .iter()
                .flat_map(|(name, bits)| (0..*bits).map(move |i| format!("{}_{}", name, i)))
                .collect()
        };

        let headers = PayloadHeader::get_headers();
        assert_eq!(
            headers.len(),
            expected_headers.len(),
            "Header count doesn't match expected."
        );
        for (i, expected) in expected_headers.iter().enumerate() {
            assert_eq!(
                headers[i], *expected,
                "Header at index {} does not match expected.",
                i
            );
        }
    }

    #[test]
    fn test_payload_header_bad_header() {
        let raw_packet: Vec<u8> = vec![0x45; 2000];
        let payload_header = PayloadHeader::new(&raw_packet);
        assert_eq!(
            payload_header,
            PayloadHeader::default(),
            "Expected data to be default."
        );
    }
}
