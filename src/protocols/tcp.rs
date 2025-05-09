use crate::protocols::packet::PacketHeader;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

/// Implementation of TCP header.
///
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct TcpHeader {
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

impl PacketHeader for TcpHeader {
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

    /// Returns a reference to the extracted data, or the default header if the extraction failed.
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

    ///  Anonymize port source and destination
    fn anonymize(&mut self) {
        self.remove(0, 15); // Port source
        self.remove(16, 31); // Port destination
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

/// Converts raw options bytes into a bit vector of 320 `f32`.
///
/// Fill with `-1.0` all the fields not present.
///
/// # Arguments
/// * `options` - Slice of bits from the option field of an Tcp header.
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
mod tcp_header_tests {
    use super::*;

    #[test]
    fn test_tcp_header_creation() {
        let raw_packet: Vec<u8> = vec![
            0xde, 0x92, 0x01, 0xbb, 0x72, 0x07, 0xf6, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02,
            0x20, 0x00, 0x05, 0x24, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02,
            0x01, 0x01, 0x04, 0x02,
        ];
        let tcp_header = TcpHeader::new(&raw_packet);
        //assert_eq!(Tcp_header.get_data().len(), 480, "Expected 480 bits in TcpHeader data.");
        let tcp_header_test = vec![
            1., 1., 0., 1., 1., 1., 1., 0., 1., 0., 0., 1., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0.,
            0., 1., 1., 0., 1., 1., 1., 0., 1., 1., 0., 1., 1., 1., 0., 0., 1., 0., 0., 0., 0., 0.,
            0., 1., 1., 1., 1., 1., 1., 1., 0., 1., 1., 0., 1., 0., 1., 0., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            1., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 1., 0., 1., 0., 0., 1., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 1., 0., 0.,
            0., 0., 0., 0., 0., 1., 0., 1., 1., 0., 1., 1., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0.,
            0., 1., 0., 0., 0., 0., 0., 0., 1., 1., 0., 0., 0., 0., 0., 0., 1., 1., 0., 0., 0., 0.,
            0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 1., 0., 0.,
            0., 0., 0., 1., 0., 0., 0., 0., 0., 0., 0., 0., 1., 0., -1., -1., -1., -1., -1., -1.,
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
            -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1., -1.,
        ];

        let data = tcp_header.get_data();
        println!("{:?}", data);
        for i in 0..tcp_header_test.len() {
            assert_eq!(
                data[i], tcp_header_test[i],
                "Tcp header doesn't match expected on bit {}.",
                i
            );
        }
    }

    #[test]
    fn test_tcp_header_get_headers() {
        let expected_headers = vec![
            "tcp_sprt_0",
            "tcp_sprt_1",
            "tcp_sprt_2",
            "tcp_sprt_3",
            "tcp_sprt_4",
            "tcp_sprt_5",
            "tcp_sprt_6",
            "tcp_sprt_7",
            "tcp_sprt_8",
            "tcp_sprt_9",
            "tcp_sprt_10",
            "tcp_sprt_11",
            "tcp_sprt_12",
            "tcp_sprt_13",
            "tcp_sprt_14",
            "tcp_sprt_15",
            "tcp_dprt_0",
            "tcp_dprt_1",
            "tcp_dprt_2",
            "tcp_dprt_3",
            "tcp_dprt_4",
            "tcp_dprt_5",
            "tcp_dprt_6",
            "tcp_dprt_7",
            "tcp_dprt_8",
            "tcp_dprt_9",
            "tcp_dprt_10",
            "tcp_dprt_11",
            "tcp_dprt_12",
            "tcp_dprt_13",
            "tcp_dprt_14",
            "tcp_dprt_15",
            "tcp_seq_0",
            "tcp_seq_1",
            "tcp_seq_2",
            "tcp_seq_3",
            "tcp_seq_4",
            "tcp_seq_5",
            "tcp_seq_6",
            "tcp_seq_7",
            "tcp_seq_8",
            "tcp_seq_9",
            "tcp_seq_10",
            "tcp_seq_11",
            "tcp_seq_12",
            "tcp_seq_13",
            "tcp_seq_14",
            "tcp_seq_15",
            "tcp_seq_16",
            "tcp_seq_17",
            "tcp_seq_18",
            "tcp_seq_19",
            "tcp_seq_20",
            "tcp_seq_21",
            "tcp_seq_22",
            "tcp_seq_23",
            "tcp_seq_24",
            "tcp_seq_25",
            "tcp_seq_26",
            "tcp_seq_27",
            "tcp_seq_28",
            "tcp_seq_29",
            "tcp_seq_30",
            "tcp_seq_31",
            "tcp_ackn_0",
            "tcp_ackn_1",
            "tcp_ackn_2",
            "tcp_ackn_3",
            "tcp_ackn_4",
            "tcp_ackn_5",
            "tcp_ackn_6",
            "tcp_ackn_7",
            "tcp_ackn_8",
            "tcp_ackn_9",
            "tcp_ackn_10",
            "tcp_ackn_11",
            "tcp_ackn_12",
            "tcp_ackn_13",
            "tcp_ackn_14",
            "tcp_ackn_15",
            "tcp_ackn_16",
            "tcp_ackn_17",
            "tcp_ackn_18",
            "tcp_ackn_19",
            "tcp_ackn_20",
            "tcp_ackn_21",
            "tcp_ackn_22",
            "tcp_ackn_23",
            "tcp_ackn_24",
            "tcp_ackn_25",
            "tcp_ackn_26",
            "tcp_ackn_27",
            "tcp_ackn_28",
            "tcp_ackn_29",
            "tcp_ackn_30",
            "tcp_ackn_31",
            "tcp_doff_0",
            "tcp_doff_1",
            "tcp_doff_2",
            "tcp_doff_3",
            "tcp_res_0",
            "tcp_res_1",
            "tcp_res_2",
            "tcp_ns_0",
            "tcp_cwr_0",
            "tcp_ece_0",
            "tcp_urg_0",
            "tcp_ackf_0",
            "tcp_psh_0",
            "tcp_rst_0",
            "tcp_syn_0",
            "tcp_fin_0",
            "tcp_wsize_0",
            "tcp_wsize_1",
            "tcp_wsize_2",
            "tcp_wsize_3",
            "tcp_wsize_4",
            "tcp_wsize_5",
            "tcp_wsize_6",
            "tcp_wsize_7",
            "tcp_wsize_8",
            "tcp_wsize_9",
            "tcp_wsize_10",
            "tcp_wsize_11",
            "tcp_wsize_12",
            "tcp_wsize_13",
            "tcp_wsize_14",
            "tcp_wsize_15",
            "tcp_cksum_0",
            "tcp_cksum_1",
            "tcp_cksum_2",
            "tcp_cksum_3",
            "tcp_cksum_4",
            "tcp_cksum_5",
            "tcp_cksum_6",
            "tcp_cksum_7",
            "tcp_cksum_8",
            "tcp_cksum_9",
            "tcp_cksum_10",
            "tcp_cksum_11",
            "tcp_cksum_12",
            "tcp_cksum_13",
            "tcp_cksum_14",
            "tcp_cksum_15",
            "tcp_urp_0",
            "tcp_urp_1",
            "tcp_urp_2",
            "tcp_urp_3",
            "tcp_urp_4",
            "tcp_urp_5",
            "tcp_urp_6",
            "tcp_urp_7",
            "tcp_urp_8",
            "tcp_urp_9",
            "tcp_urp_10",
            "tcp_urp_11",
            "tcp_urp_12",
            "tcp_urp_13",
            "tcp_urp_14",
            "tcp_urp_15",
            "tcp_opt_0",
            "tcp_opt_1",
            "tcp_opt_2",
            "tcp_opt_3",
            "tcp_opt_4",
            "tcp_opt_5",
            "tcp_opt_6",
            "tcp_opt_7",
            "tcp_opt_8",
            "tcp_opt_9",
            "tcp_opt_10",
            "tcp_opt_11",
            "tcp_opt_12",
            "tcp_opt_13",
            "tcp_opt_14",
            "tcp_opt_15",
            "tcp_opt_16",
            "tcp_opt_17",
            "tcp_opt_18",
            "tcp_opt_19",
            "tcp_opt_20",
            "tcp_opt_21",
            "tcp_opt_22",
            "tcp_opt_23",
            "tcp_opt_24",
            "tcp_opt_25",
            "tcp_opt_26",
            "tcp_opt_27",
            "tcp_opt_28",
            "tcp_opt_29",
            "tcp_opt_30",
            "tcp_opt_31",
            "tcp_opt_32",
            "tcp_opt_33",
            "tcp_opt_34",
            "tcp_opt_35",
            "tcp_opt_36",
            "tcp_opt_37",
            "tcp_opt_38",
            "tcp_opt_39",
            "tcp_opt_40",
            "tcp_opt_41",
            "tcp_opt_42",
            "tcp_opt_43",
            "tcp_opt_44",
            "tcp_opt_45",
            "tcp_opt_46",
            "tcp_opt_47",
            "tcp_opt_48",
            "tcp_opt_49",
            "tcp_opt_50",
            "tcp_opt_51",
            "tcp_opt_52",
            "tcp_opt_53",
            "tcp_opt_54",
            "tcp_opt_55",
            "tcp_opt_56",
            "tcp_opt_57",
            "tcp_opt_58",
            "tcp_opt_59",
            "tcp_opt_60",
            "tcp_opt_61",
            "tcp_opt_62",
            "tcp_opt_63",
            "tcp_opt_64",
            "tcp_opt_65",
            "tcp_opt_66",
            "tcp_opt_67",
            "tcp_opt_68",
            "tcp_opt_69",
            "tcp_opt_70",
            "tcp_opt_71",
            "tcp_opt_72",
            "tcp_opt_73",
            "tcp_opt_74",
            "tcp_opt_75",
            "tcp_opt_76",
            "tcp_opt_77",
            "tcp_opt_78",
            "tcp_opt_79",
            "tcp_opt_80",
            "tcp_opt_81",
            "tcp_opt_82",
            "tcp_opt_83",
            "tcp_opt_84",
            "tcp_opt_85",
            "tcp_opt_86",
            "tcp_opt_87",
            "tcp_opt_88",
            "tcp_opt_89",
            "tcp_opt_90",
            "tcp_opt_91",
            "tcp_opt_92",
            "tcp_opt_93",
            "tcp_opt_94",
            "tcp_opt_95",
            "tcp_opt_96",
            "tcp_opt_97",
            "tcp_opt_98",
            "tcp_opt_99",
            "tcp_opt_100",
            "tcp_opt_101",
            "tcp_opt_102",
            "tcp_opt_103",
            "tcp_opt_104",
            "tcp_opt_105",
            "tcp_opt_106",
            "tcp_opt_107",
            "tcp_opt_108",
            "tcp_opt_109",
            "tcp_opt_110",
            "tcp_opt_111",
            "tcp_opt_112",
            "tcp_opt_113",
            "tcp_opt_114",
            "tcp_opt_115",
            "tcp_opt_116",
            "tcp_opt_117",
            "tcp_opt_118",
            "tcp_opt_119",
            "tcp_opt_120",
            "tcp_opt_121",
            "tcp_opt_122",
            "tcp_opt_123",
            "tcp_opt_124",
            "tcp_opt_125",
            "tcp_opt_126",
            "tcp_opt_127",
            "tcp_opt_128",
            "tcp_opt_129",
            "tcp_opt_130",
            "tcp_opt_131",
            "tcp_opt_132",
            "tcp_opt_133",
            "tcp_opt_134",
            "tcp_opt_135",
            "tcp_opt_136",
            "tcp_opt_137",
            "tcp_opt_138",
            "tcp_opt_139",
            "tcp_opt_140",
            "tcp_opt_141",
            "tcp_opt_142",
            "tcp_opt_143",
            "tcp_opt_144",
            "tcp_opt_145",
            "tcp_opt_146",
            "tcp_opt_147",
            "tcp_opt_148",
            "tcp_opt_149",
            "tcp_opt_150",
            "tcp_opt_151",
            "tcp_opt_152",
            "tcp_opt_153",
            "tcp_opt_154",
            "tcp_opt_155",
            "tcp_opt_156",
            "tcp_opt_157",
            "tcp_opt_158",
            "tcp_opt_159",
            "tcp_opt_160",
            "tcp_opt_161",
            "tcp_opt_162",
            "tcp_opt_163",
            "tcp_opt_164",
            "tcp_opt_165",
            "tcp_opt_166",
            "tcp_opt_167",
            "tcp_opt_168",
            "tcp_opt_169",
            "tcp_opt_170",
            "tcp_opt_171",
            "tcp_opt_172",
            "tcp_opt_173",
            "tcp_opt_174",
            "tcp_opt_175",
            "tcp_opt_176",
            "tcp_opt_177",
            "tcp_opt_178",
            "tcp_opt_179",
            "tcp_opt_180",
            "tcp_opt_181",
            "tcp_opt_182",
            "tcp_opt_183",
            "tcp_opt_184",
            "tcp_opt_185",
            "tcp_opt_186",
            "tcp_opt_187",
            "tcp_opt_188",
            "tcp_opt_189",
            "tcp_opt_190",
            "tcp_opt_191",
            "tcp_opt_192",
            "tcp_opt_193",
            "tcp_opt_194",
            "tcp_opt_195",
            "tcp_opt_196",
            "tcp_opt_197",
            "tcp_opt_198",
            "tcp_opt_199",
            "tcp_opt_200",
            "tcp_opt_201",
            "tcp_opt_202",
            "tcp_opt_203",
            "tcp_opt_204",
            "tcp_opt_205",
            "tcp_opt_206",
            "tcp_opt_207",
            "tcp_opt_208",
            "tcp_opt_209",
            "tcp_opt_210",
            "tcp_opt_211",
            "tcp_opt_212",
            "tcp_opt_213",
            "tcp_opt_214",
            "tcp_opt_215",
            "tcp_opt_216",
            "tcp_opt_217",
            "tcp_opt_218",
            "tcp_opt_219",
            "tcp_opt_220",
            "tcp_opt_221",
            "tcp_opt_222",
            "tcp_opt_223",
            "tcp_opt_224",
            "tcp_opt_225",
            "tcp_opt_226",
            "tcp_opt_227",
            "tcp_opt_228",
            "tcp_opt_229",
            "tcp_opt_230",
            "tcp_opt_231",
            "tcp_opt_232",
            "tcp_opt_233",
            "tcp_opt_234",
            "tcp_opt_235",
            "tcp_opt_236",
            "tcp_opt_237",
            "tcp_opt_238",
            "tcp_opt_239",
            "tcp_opt_240",
            "tcp_opt_241",
            "tcp_opt_242",
            "tcp_opt_243",
            "tcp_opt_244",
            "tcp_opt_245",
            "tcp_opt_246",
            "tcp_opt_247",
            "tcp_opt_248",
            "tcp_opt_249",
            "tcp_opt_250",
            "tcp_opt_251",
            "tcp_opt_252",
            "tcp_opt_253",
            "tcp_opt_254",
            "tcp_opt_255",
            "tcp_opt_256",
            "tcp_opt_257",
            "tcp_opt_258",
            "tcp_opt_259",
            "tcp_opt_260",
            "tcp_opt_261",
            "tcp_opt_262",
            "tcp_opt_263",
            "tcp_opt_264",
            "tcp_opt_265",
            "tcp_opt_266",
            "tcp_opt_267",
            "tcp_opt_268",
            "tcp_opt_269",
            "tcp_opt_270",
            "tcp_opt_271",
            "tcp_opt_272",
            "tcp_opt_273",
            "tcp_opt_274",
            "tcp_opt_275",
            "tcp_opt_276",
            "tcp_opt_277",
            "tcp_opt_278",
            "tcp_opt_279",
            "tcp_opt_280",
            "tcp_opt_281",
            "tcp_opt_282",
            "tcp_opt_283",
            "tcp_opt_284",
            "tcp_opt_285",
            "tcp_opt_286",
            "tcp_opt_287",
            "tcp_opt_288",
            "tcp_opt_289",
            "tcp_opt_290",
            "tcp_opt_291",
            "tcp_opt_292",
            "tcp_opt_293",
            "tcp_opt_294",
            "tcp_opt_295",
            "tcp_opt_296",
            "tcp_opt_297",
            "tcp_opt_298",
            "tcp_opt_299",
            "tcp_opt_300",
            "tcp_opt_301",
            "tcp_opt_302",
            "tcp_opt_303",
            "tcp_opt_304",
            "tcp_opt_305",
            "tcp_opt_306",
            "tcp_opt_307",
            "tcp_opt_308",
            "tcp_opt_309",
            "tcp_opt_310",
            "tcp_opt_311",
            "tcp_opt_312",
            "tcp_opt_313",
            "tcp_opt_314",
            "tcp_opt_315",
            "tcp_opt_316",
            "tcp_opt_317",
            "tcp_opt_318",
            "tcp_opt_319",
        ];

        let headers = TcpHeader::get_headers();
        for (i, expected) in expected_headers.iter().enumerate() {
            assert_eq!(
                headers[i], *expected,
                "Header at index {} does not match expected.",
                i
            );
        }
    }

    #[test]
    fn test_tcp_header_bad_header() {
        let raw_packet: Vec<u8> = vec![0x45, 0x00, 0x00, 0x3c, 0xf5, 0x1b];
        let tcp_header = TcpHeader::new(&raw_packet);
        assert_eq!(
            tcp_header,
            TcpHeader::default(),
            "Expected data to be default."
        );
    }

    #[test]
    fn test_tcp_header_anonymize() {
        let raw_packet: Vec<u8> = vec![
            0xde, 0x92, 0x01, 0xbb, 0x72, 0x07, 0xf6, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02,
            0x20, 0x00, 0x05, 0x24, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x02,
            0x01, 0x01, 0x04, 0x02,
        ];
        let mut tcp_header = TcpHeader::new(&raw_packet);
        tcp_header.anonymize();
        let anon = tcp_header.get_data();
        for ip_bit in anon.iter().take(0).skip(32) {
            assert_eq!(*ip_bit, 0., "Expected data bit 0-31 to be 0.");
        }
    }
}
