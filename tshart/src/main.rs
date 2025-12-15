use clap::Parser;
use pcap_parser_lib::PcapPointerIterator;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the PCAPNG file
    #[arg(short, long)]
    pcap_path: String,
}

pub fn main() {
    let args = Args::parse();
    let pcap_path = args.pcap_path;

    for pcap in PcapPointerIterator::new(pcap_path) {
        println!("{:?}", pcap);
    }
}
