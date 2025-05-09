use crate::protocols::packet::PacketHeader;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;

/// Implementation of IPv4 header.
///
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Ipv4Header {
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

impl PacketHeader for Ipv4Header {
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
    fn get_headers() -> Vec<String> {
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

    /// Remove IPs to anonymized header.
    fn anonymize(&mut self) {
        self.remove(96, 127); // IP Source
        self.remove(128, 159); // IP Destination
    }
}

impl Ipv4Header {
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

#[cfg(test)]
mod ipv4_header_tests {
    use super::*;

    #[test]
    fn test_ipv4_header_creation() {
        let raw_packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x3c, 0xf5, 0x1b, 0x40, 0x00, 0x40, 0x06, 0x1b, 0x24, 0xc0, 0xa8,
            0x2b, 0x25, 0xc6, 0x26, 0x78, 0x88, 0x97, 0xa4, 0x01, 0xbb, 0x96, 0x2e, 0x5e, 0x0b,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x25, 0xd4, 0x00, 0x00, 0x02, 0x04,
            0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xe3, 0xe2, 0x14, 0x23, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x03, 0x03, 0x07,
        ];
        let ipv4_header = Ipv4Header::new(&raw_packet);
        //assert_eq!(ipv4_header.get_data().len(), 480, "Expected 480 bits in Ipv4Header data.");
        let ipv4_header_test = vec![
            0., 1., 0., 0., 0., 1., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 0., 1., 1., 1., 1., 0., 0., 1., 1., 1., 1., 0., 1., 0., 1., 0., 0., 0., 1.,
            1., 0., 1., 1., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 1., 0., 0., 0., 0., 1., 1., 0., 1., 1.,
            0., 0., 1., 0., 0., 1., 0., 0., 1., 1., 0., 0., 0., 0., 0., 0., 1., 0., 1., 0., 1., 0.,
            0., 0., 0., 0., 1., 0., 1., 0., 1., 1., 0., 0., 1., 0., 0., 1., 0., 1., 1., 1., 0., 0.,
            0., 1., 1., 0., 0., 0., 1., 0., 0., 1., 1., 0., 0., 1., 1., 1., 1., 0., 0., 0., 1., 0.,
            0., 0., 1., 0., 0., 0., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1.,
        ];

        let data = ipv4_header.get_data();
        for i in 0..ipv4_header_test.len() {
            assert_eq!(
                data[i], ipv4_header_test[i],
                "IPv4 header doesn't match expected on bit {}.",
                i
            );
        }
    }

    #[test]
    fn test_ipv4_header_get_headers() {
        let expected_headers = vec![
            "ipv4_ver_0",
            "ipv4_ver_1",
            "ipv4_ver_2",
            "ipv4_ver_3",
            "ipv4_hl_0",
            "ipv4_hl_1",
            "ipv4_hl_2",
            "ipv4_hl_3",
            "ipv4_tos_0",
            "ipv4_tos_1",
            "ipv4_tos_2",
            "ipv4_tos_3",
            "ipv4_tos_4",
            "ipv4_tos_5",
            "ipv4_tos_6",
            "ipv4_tos_7",
            "ipv4_tl_0",
            "ipv4_tl_1",
            "ipv4_tl_2",
            "ipv4_tl_3",
            "ipv4_tl_4",
            "ipv4_tl_5",
            "ipv4_tl_6",
            "ipv4_tl_7",
            "ipv4_tl_8",
            "ipv4_tl_9",
            "ipv4_tl_10",
            "ipv4_tl_11",
            "ipv4_tl_12",
            "ipv4_tl_13",
            "ipv4_tl_14",
            "ipv4_tl_15",
            "ipv4_id_0",
            "ipv4_id_1",
            "ipv4_id_2",
            "ipv4_id_3",
            "ipv4_id_4",
            "ipv4_id_5",
            "ipv4_id_6",
            "ipv4_id_7",
            "ipv4_id_8",
            "ipv4_id_9",
            "ipv4_id_10",
            "ipv4_id_11",
            "ipv4_id_12",
            "ipv4_id_13",
            "ipv4_id_14",
            "ipv4_id_15",
            "ipv4_rbit_0",
            "ipv4_dfbit_0",
            "ipv4_mfbit_0",
            "ipv4_foff_0",
            "ipv4_foff_1",
            "ipv4_foff_2",
            "ipv4_foff_3",
            "ipv4_foff_4",
            "ipv4_foff_5",
            "ipv4_foff_6",
            "ipv4_foff_7",
            "ipv4_foff_8",
            "ipv4_foff_9",
            "ipv4_foff_10",
            "ipv4_foff_11",
            "ipv4_foff_12",
            "ipv4_ttl_0",
            "ipv4_ttl_1",
            "ipv4_ttl_2",
            "ipv4_ttl_3",
            "ipv4_ttl_4",
            "ipv4_ttl_5",
            "ipv4_ttl_6",
            "ipv4_ttl_7",
            "ipv4_proto_0",
            "ipv4_proto_1",
            "ipv4_proto_2",
            "ipv4_proto_3",
            "ipv4_proto_4",
            "ipv4_proto_5",
            "ipv4_proto_6",
            "ipv4_proto_7",
            "ipv4_cksum_0",
            "ipv4_cksum_1",
            "ipv4_cksum_2",
            "ipv4_cksum_3",
            "ipv4_cksum_4",
            "ipv4_cksum_5",
            "ipv4_cksum_6",
            "ipv4_cksum_7",
            "ipv4_cksum_8",
            "ipv4_cksum_9",
            "ipv4_cksum_10",
            "ipv4_cksum_11",
            "ipv4_cksum_12",
            "ipv4_cksum_13",
            "ipv4_cksum_14",
            "ipv4_cksum_15",
            "ipv4_src_0",
            "ipv4_src_1",
            "ipv4_src_2",
            "ipv4_src_3",
            "ipv4_src_4",
            "ipv4_src_5",
            "ipv4_src_6",
            "ipv4_src_7",
            "ipv4_src_8",
            "ipv4_src_9",
            "ipv4_src_10",
            "ipv4_src_11",
            "ipv4_src_12",
            "ipv4_src_13",
            "ipv4_src_14",
            "ipv4_src_15",
            "ipv4_src_16",
            "ipv4_src_17",
            "ipv4_src_18",
            "ipv4_src_19",
            "ipv4_src_20",
            "ipv4_src_21",
            "ipv4_src_22",
            "ipv4_src_23",
            "ipv4_src_24",
            "ipv4_src_25",
            "ipv4_src_26",
            "ipv4_src_27",
            "ipv4_src_28",
            "ipv4_src_29",
            "ipv4_src_30",
            "ipv4_src_31",
            "ipv4_dst_0",
            "ipv4_dst_1",
            "ipv4_dst_2",
            "ipv4_dst_3",
            "ipv4_dst_4",
            "ipv4_dst_5",
            "ipv4_dst_6",
            "ipv4_dst_7",
            "ipv4_dst_8",
            "ipv4_dst_9",
            "ipv4_dst_10",
            "ipv4_dst_11",
            "ipv4_dst_12",
            "ipv4_dst_13",
            "ipv4_dst_14",
            "ipv4_dst_15",
            "ipv4_dst_16",
            "ipv4_dst_17",
            "ipv4_dst_18",
            "ipv4_dst_19",
            "ipv4_dst_20",
            "ipv4_dst_21",
            "ipv4_dst_22",
            "ipv4_dst_23",
            "ipv4_dst_24",
            "ipv4_dst_25",
            "ipv4_dst_26",
            "ipv4_dst_27",
            "ipv4_dst_28",
            "ipv4_dst_29",
            "ipv4_dst_30",
            "ipv4_dst_31",
            "ipv4_opt_0",
            "ipv4_opt_1",
            "ipv4_opt_2",
            "ipv4_opt_3",
            "ipv4_opt_4",
            "ipv4_opt_5",
            "ipv4_opt_6",
            "ipv4_opt_7",
            "ipv4_opt_8",
            "ipv4_opt_9",
            "ipv4_opt_10",
            "ipv4_opt_11",
            "ipv4_opt_12",
            "ipv4_opt_13",
            "ipv4_opt_14",
            "ipv4_opt_15",
            "ipv4_opt_16",
            "ipv4_opt_17",
            "ipv4_opt_18",
            "ipv4_opt_19",
            "ipv4_opt_20",
            "ipv4_opt_21",
            "ipv4_opt_22",
            "ipv4_opt_23",
            "ipv4_opt_24",
            "ipv4_opt_25",
            "ipv4_opt_26",
            "ipv4_opt_27",
            "ipv4_opt_28",
            "ipv4_opt_29",
            "ipv4_opt_30",
            "ipv4_opt_31",
            "ipv4_opt_32",
            "ipv4_opt_33",
            "ipv4_opt_34",
            "ipv4_opt_35",
            "ipv4_opt_36",
            "ipv4_opt_37",
            "ipv4_opt_38",
            "ipv4_opt_39",
            "ipv4_opt_40",
            "ipv4_opt_41",
            "ipv4_opt_42",
            "ipv4_opt_43",
            "ipv4_opt_44",
            "ipv4_opt_45",
            "ipv4_opt_46",
            "ipv4_opt_47",
            "ipv4_opt_48",
            "ipv4_opt_49",
            "ipv4_opt_50",
            "ipv4_opt_51",
            "ipv4_opt_52",
            "ipv4_opt_53",
            "ipv4_opt_54",
            "ipv4_opt_55",
            "ipv4_opt_56",
            "ipv4_opt_57",
            "ipv4_opt_58",
            "ipv4_opt_59",
            "ipv4_opt_60",
            "ipv4_opt_61",
            "ipv4_opt_62",
            "ipv4_opt_63",
            "ipv4_opt_64",
            "ipv4_opt_65",
            "ipv4_opt_66",
            "ipv4_opt_67",
            "ipv4_opt_68",
            "ipv4_opt_69",
            "ipv4_opt_70",
            "ipv4_opt_71",
            "ipv4_opt_72",
            "ipv4_opt_73",
            "ipv4_opt_74",
            "ipv4_opt_75",
            "ipv4_opt_76",
            "ipv4_opt_77",
            "ipv4_opt_78",
            "ipv4_opt_79",
            "ipv4_opt_80",
            "ipv4_opt_81",
            "ipv4_opt_82",
            "ipv4_opt_83",
            "ipv4_opt_84",
            "ipv4_opt_85",
            "ipv4_opt_86",
            "ipv4_opt_87",
            "ipv4_opt_88",
            "ipv4_opt_89",
            "ipv4_opt_90",
            "ipv4_opt_91",
            "ipv4_opt_92",
            "ipv4_opt_93",
            "ipv4_opt_94",
            "ipv4_opt_95",
            "ipv4_opt_96",
            "ipv4_opt_97",
            "ipv4_opt_98",
            "ipv4_opt_99",
            "ipv4_opt_100",
            "ipv4_opt_101",
            "ipv4_opt_102",
            "ipv4_opt_103",
            "ipv4_opt_104",
            "ipv4_opt_105",
            "ipv4_opt_106",
            "ipv4_opt_107",
            "ipv4_opt_108",
            "ipv4_opt_109",
            "ipv4_opt_110",
            "ipv4_opt_111",
            "ipv4_opt_112",
            "ipv4_opt_113",
            "ipv4_opt_114",
            "ipv4_opt_115",
            "ipv4_opt_116",
            "ipv4_opt_117",
            "ipv4_opt_118",
            "ipv4_opt_119",
            "ipv4_opt_120",
            "ipv4_opt_121",
            "ipv4_opt_122",
            "ipv4_opt_123",
            "ipv4_opt_124",
            "ipv4_opt_125",
            "ipv4_opt_126",
            "ipv4_opt_127",
            "ipv4_opt_128",
            "ipv4_opt_129",
            "ipv4_opt_130",
            "ipv4_opt_131",
            "ipv4_opt_132",
            "ipv4_opt_133",
            "ipv4_opt_134",
            "ipv4_opt_135",
            "ipv4_opt_136",
            "ipv4_opt_137",
            "ipv4_opt_138",
            "ipv4_opt_139",
            "ipv4_opt_140",
            "ipv4_opt_141",
            "ipv4_opt_142",
            "ipv4_opt_143",
            "ipv4_opt_144",
            "ipv4_opt_145",
            "ipv4_opt_146",
            "ipv4_opt_147",
            "ipv4_opt_148",
            "ipv4_opt_149",
            "ipv4_opt_150",
            "ipv4_opt_151",
            "ipv4_opt_152",
            "ipv4_opt_153",
            "ipv4_opt_154",
            "ipv4_opt_155",
            "ipv4_opt_156",
            "ipv4_opt_157",
            "ipv4_opt_158",
            "ipv4_opt_159",
            "ipv4_opt_160",
            "ipv4_opt_161",
            "ipv4_opt_162",
            "ipv4_opt_163",
            "ipv4_opt_164",
            "ipv4_opt_165",
            "ipv4_opt_166",
            "ipv4_opt_167",
            "ipv4_opt_168",
            "ipv4_opt_169",
            "ipv4_opt_170",
            "ipv4_opt_171",
            "ipv4_opt_172",
            "ipv4_opt_173",
            "ipv4_opt_174",
            "ipv4_opt_175",
            "ipv4_opt_176",
            "ipv4_opt_177",
            "ipv4_opt_178",
            "ipv4_opt_179",
            "ipv4_opt_180",
            "ipv4_opt_181",
            "ipv4_opt_182",
            "ipv4_opt_183",
            "ipv4_opt_184",
            "ipv4_opt_185",
            "ipv4_opt_186",
            "ipv4_opt_187",
            "ipv4_opt_188",
            "ipv4_opt_189",
            "ipv4_opt_190",
            "ipv4_opt_191",
            "ipv4_opt_192",
            "ipv4_opt_193",
            "ipv4_opt_194",
            "ipv4_opt_195",
            "ipv4_opt_196",
            "ipv4_opt_197",
            "ipv4_opt_198",
            "ipv4_opt_199",
            "ipv4_opt_200",
            "ipv4_opt_201",
            "ipv4_opt_202",
            "ipv4_opt_203",
            "ipv4_opt_204",
            "ipv4_opt_205",
            "ipv4_opt_206",
            "ipv4_opt_207",
            "ipv4_opt_208",
            "ipv4_opt_209",
            "ipv4_opt_210",
            "ipv4_opt_211",
            "ipv4_opt_212",
            "ipv4_opt_213",
            "ipv4_opt_214",
            "ipv4_opt_215",
            "ipv4_opt_216",
            "ipv4_opt_217",
            "ipv4_opt_218",
            "ipv4_opt_219",
            "ipv4_opt_220",
            "ipv4_opt_221",
            "ipv4_opt_222",
            "ipv4_opt_223",
            "ipv4_opt_224",
            "ipv4_opt_225",
            "ipv4_opt_226",
            "ipv4_opt_227",
            "ipv4_opt_228",
            "ipv4_opt_229",
            "ipv4_opt_230",
            "ipv4_opt_231",
            "ipv4_opt_232",
            "ipv4_opt_233",
            "ipv4_opt_234",
            "ipv4_opt_235",
            "ipv4_opt_236",
            "ipv4_opt_237",
            "ipv4_opt_238",
            "ipv4_opt_239",
            "ipv4_opt_240",
            "ipv4_opt_241",
            "ipv4_opt_242",
            "ipv4_opt_243",
            "ipv4_opt_244",
            "ipv4_opt_245",
            "ipv4_opt_246",
            "ipv4_opt_247",
            "ipv4_opt_248",
            "ipv4_opt_249",
            "ipv4_opt_250",
            "ipv4_opt_251",
            "ipv4_opt_252",
            "ipv4_opt_253",
            "ipv4_opt_254",
            "ipv4_opt_255",
            "ipv4_opt_256",
            "ipv4_opt_257",
            "ipv4_opt_258",
            "ipv4_opt_259",
            "ipv4_opt_260",
            "ipv4_opt_261",
            "ipv4_opt_262",
            "ipv4_opt_263",
            "ipv4_opt_264",
            "ipv4_opt_265",
            "ipv4_opt_266",
            "ipv4_opt_267",
            "ipv4_opt_268",
            "ipv4_opt_269",
            "ipv4_opt_270",
            "ipv4_opt_271",
            "ipv4_opt_272",
            "ipv4_opt_273",
            "ipv4_opt_274",
            "ipv4_opt_275",
            "ipv4_opt_276",
            "ipv4_opt_277",
            "ipv4_opt_278",
            "ipv4_opt_279",
            "ipv4_opt_280",
            "ipv4_opt_281",
            "ipv4_opt_282",
            "ipv4_opt_283",
            "ipv4_opt_284",
            "ipv4_opt_285",
            "ipv4_opt_286",
            "ipv4_opt_287",
            "ipv4_opt_288",
            "ipv4_opt_289",
            "ipv4_opt_290",
            "ipv4_opt_291",
            "ipv4_opt_292",
            "ipv4_opt_293",
            "ipv4_opt_294",
            "ipv4_opt_295",
            "ipv4_opt_296",
            "ipv4_opt_297",
            "ipv4_opt_298",
            "ipv4_opt_299",
            "ipv4_opt_300",
            "ipv4_opt_301",
            "ipv4_opt_302",
            "ipv4_opt_303",
            "ipv4_opt_304",
            "ipv4_opt_305",
            "ipv4_opt_306",
            "ipv4_opt_307",
            "ipv4_opt_308",
            "ipv4_opt_309",
            "ipv4_opt_310",
            "ipv4_opt_311",
            "ipv4_opt_312",
            "ipv4_opt_313",
            "ipv4_opt_314",
            "ipv4_opt_315",
            "ipv4_opt_316",
            "ipv4_opt_317",
            "ipv4_opt_318",
            "ipv4_opt_319",
        ];

        let headers = Ipv4Header::get_headers();
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
    fn test_ipv4_header_options() {
        let raw_packet: Vec<u8> = vec![
            0x4b, 0x0, 0x0, 0x6c, 0x78, 0x37, 0x0, 0x0, 0x40, 0x1, 0x75, 0x2d, 0x7f, 0x0, 0x0, 0x1,
            0x7f, 0x0, 0x0, 0x1, 0x86, 0x16, 0x0, 0x0, 0x0, 0x2, 0x2, 0x10, 0x0, 0x2, 0x0, 0x0,
            0x0, 0x2, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6, 0x0, 0xef, 0x0, 0x0,
        ];
        let ipv4_header = Ipv4Header::new(&raw_packet);
        let ipv4_header_test = vec![
            0., 1., 0., 0., 1., 0., 1., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 1., 1., 0., 1., 1., 0., 0., 0., 1., 1., 1., 1., 0., 0., 0., 0., 0., 1., 1.,
            0., 1., 1., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 1., 1., 1., 0., 1., 0., 1.,
            0., 0., 1., 0., 1., 1., 0., 1., 0., 1., 1., 1., 1., 1., 1., 1., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 1., 1., 1.,
            1., 1., 1., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 0., 0., 1., 1., 0., 0., 0., 0., 1., 1., 0., 0., 0., 0., 1., 0., 1., 1., 0.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 1.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 1., 0., 0., 0., 0.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 1.,
            1., 0., 1., 1., 1., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
            -1., -1., -1., -1., -1., -1., -1., -1., -1.,
        ];
        let data = ipv4_header.get_data();
        for i in 0..ipv4_header_test.len() {
            assert_eq!(
                data[i], ipv4_header_test[i],
                "IPv4 header doesn't match expected on bit {}.",
                i
            );
        }
    }

    #[test]
    fn test_ipv4_header_bad_header() {
        let raw_packet: Vec<u8> = vec![0x45, 0x00, 0x00, 0x3c, 0xf5, 0x1b];
        let ipv4_header = Ipv4Header::new(&raw_packet);
        assert_eq!(
            ipv4_header,
            Ipv4Header::default(),
            "Expected data to be default."
        );
    }

    #[test]
    fn test_ipv4_header_anonymize() {
        let raw_packet: Vec<u8> = vec![
            0x45, 0x00, 0x00, 0x3c, 0xf5, 0x1b, 0x40, 0x00, 0x40, 0x06, 0x1b, 0x24, 0xc0, 0xa8,
            0x2b, 0x25, 0xc6, 0x26, 0x78, 0x88, 0x97, 0xa4, 0x01, 0xbb, 0x96, 0x2e, 0x5e, 0x0b,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x25, 0xd4, 0x00, 0x00, 0x02, 0x04,
            0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xe3, 0xe2, 0x14, 0x23, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x03, 0x03, 0x07,
        ];
        let mut ipv4_header = Ipv4Header::new(&raw_packet);
        ipv4_header.anonymize();
        let anon = ipv4_header.get_data();
        for ip_bit in anon.iter().take(160).skip(96) {
            assert_eq!(*ip_bit, 0., "Expected data bit 96-160 to be 0.");
        }
    }
}
