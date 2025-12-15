use clap::Parser;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{PcapError, PcapNGReader};
use std::fs::File;
use std::io::BufReader;
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
    let file = File::open(args.pcap_path).unwrap();
    let reader = BufReader::new(file);
    let mut pcap_reader = PcapNGReader::new(1024 * 1024, reader).unwrap();

    let mut packet_num = 0;
    let mut first_packet_time: Option<SystemTime> = None;

    loop {
        match pcap_reader.next() {
            Ok((offset, block)) => {
                match block {
                    pcap_parser::PcapBlockOwned::NG(pcap_parser::Block::EnhancedPacket(packet)) => {
                        packet_num += 1;
                        let timestamp = (packet.ts_high as u64) << 32 | packet.ts_low as u64;
                        let system_time = SystemTime::UNIX_EPOCH
                            + std::time::Duration::from_micros(timestamp.into());
                        if first_packet_time.is_none() {
                            first_packet_time = Some(system_time);
                        }
                        let time_since_first = system_time
                            .duration_since(first_packet_time.unwrap())
                            .unwrap();

                        if let Some(parsed_packet) = packet_parser::parse_packet(packet.data) {
                            println!(
                                "{:>5} {:>10.6} {} → {} {} {} {}",
                                packet_num,
                                time_since_first.as_secs_f64(),
                                parsed_packet.src_ip,
                                parsed_packet.dst_ip,
                                parsed_packet.protocol,
                                packet.origlen,
                                format!("{}", parsed_packet.info)
                            );
                        }
                    }
                    _ => {}
                }
                pcap_reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                pcap_reader.refill().unwrap();
            }
            Err(e) => panic!("Error reading pcap file: {:?}", e),
        }
    }
}
