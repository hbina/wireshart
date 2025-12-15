#[derive(Debug, Clone)]
pub enum MainGuiMessage {
    Start,
    NewRow(Result<pcap_parser_lib::PcapPointer, String>),
    Expand(usize),
    Collapse(usize),
}
