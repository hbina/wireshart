use pcap_parser_lib::PcapPointerIterator;

#[test]
fn test_pcap_parser() {
    let mut packets = vec![];
    for pcap in PcapPointerIterator::new("tests/test.pcap".to_string()) {
        packets.push(pcap);
    }
    insta::assert_debug_snapshot!(packets);
}
