use clap::Parser;
use packet_parser::{PcapPointer, PcapPointerIterator};
use std::fs::File;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the PCAPNG file
    #[arg(short, long)]
    pcap_path: String,
}

fn main() {
    let args = Args::parse();
    let pcap_file = Arc::new(Mutex::new(File::open(&args.pcap_path).unwrap()));
    let iterator = PcapPointerIterator::new(args.pcap_path);

    let mut packet_num = 0;
    let mut first_packet_time: Option<SystemTime> = None;

    for pcap_pointer in iterator {
        packet_num += 1;

        if first_packet_time.is_none() {
            first_packet_time = Some(pcap_pointer.timestamp);
        }
        let time_since_first = pcap_pointer
            .timestamp
            .duration_since(first_packet_time.unwrap())
            .unwrap();

        if let Some(parsed_packet) =
            packet_parser::parse_from_pcap_pointer(&pcap_pointer, &pcap_file)
        {
            println!(
                "{:>5} {:>10.6} {} → {} {} {} {}",
                packet_num,
                time_since_first.as_secs_f64(),
                parsed_packet.src_ip,
                parsed_packet.dst_ip,
                parsed_packet.protocol,
                parsed_packet.len,
                format!("{}", parsed_packet.info)
            );
        }
    }
}
