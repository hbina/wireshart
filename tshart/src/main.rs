use clap::Parser;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{PcapError, PcapNGReader};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
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

                        let data = packet.data;
                        let ethernet_packet = EthernetPacket::new(&data).unwrap();
                        let (mut src_ip, mut dst_ip, mut protocol, mut info) =
                            (String::new(), String::new(), String::new(), String::new());
                        match ethernet_packet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                let ipv4_packet =
                                    Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                                src_ip = ipv4_packet.get_source().to_string();
                                dst_ip = ipv4_packet.get_destination().to_string();
                                protocol = ipv4_packet
                                    .get_next_level_protocol()
                                    .to_string()
                                    .to_uppercase();
                                match protocol.as_str() {
                                    "TCP" => {
                                        let tcp_packet =
                                            TcpPacket::new(ipv4_packet.payload()).unwrap();
                                        info = format!(
                                            "{} → {} Len={}",
                                            tcp_packet.get_source(),
                                            tcp_packet.get_destination(),
                                            ipv4_packet.payload().len()
                                                - tcp_packet.get_data_offset() as usize * 4
                                        );
                                    }
                                    "UDP" => {
                                        let udp_packet =
                                            UdpPacket::new(ipv4_packet.payload()).unwrap();
                                        info = format!(
                                            "{} → {} Len={}",
                                            udp_packet.get_source(),
                                            udp_packet.get_destination(),
                                            udp_packet.get_length() - 8
                                        );
                                    }
                                    _ => {}
                                }
                            }
                            EtherTypes::Ipv6 => {
                                let ipv6_packet =
                                    Ipv6Packet::new(ethernet_packet.payload()).unwrap();
                                src_ip = ipv6_packet.get_source().to_string();
                                dst_ip = ipv6_packet.get_destination().to_string();
                                protocol = ipv6_packet.get_next_header().to_string().to_uppercase();
                                // Similar parsing for TCP/UDP over IPv6 can be added here
                            }
                            _ => {}
                        }

                        println!(
                            "{:>5} {:>10.6} {} → {} {} {} {}",
                            packet_num,
                            time_since_first.as_secs_f64(),
                            src_ip,
                            dst_ip,
                            protocol,
                            packet.origlen,
                            info
                        );
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
