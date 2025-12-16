use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{PcapError, PcapNGReader};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{Read, Seek};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct PcapPointer {
    pub idx: usize,
    pub pcap_offset: usize,
    pub pcap_len: usize,
    pub timestamp: SystemTime,
}

pub struct PcapPointerIterator {
    pcap_reader: PcapNGReader<std::io::BufReader<std::fs::File>>,
    pcap_offset: usize,
}

impl PcapPointerIterator {
    pub fn new(file_path: String) -> Self {
        Self {
            pcap_reader: PcapNGReader::new(
                64 * 1024 * 1024,
                std::io::BufReader::new(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .open(&file_path)
                        .unwrap(),
                ),
            )
            .unwrap(),
            pcap_offset: 0,
        }
    }
}

impl Iterator for PcapPointerIterator {
    type Item = PcapPointer;

    fn next(&mut self) -> Option<Self::Item> {
        let mut idx = 0;
        loop {
            match self.pcap_reader.next() {
                Ok((current_offset, block)) => {
                    let res = match block {
                        pcap_parser::PcapBlockOwned::NG(ng) => match ng {
                            pcap_parser::Block::EnhancedPacket(b) => Some(PcapPointer {
                                idx,
                                pcap_offset: self.pcap_offset + 4 + 4 + 4 + 4 + 4 + 4 + 4,
                                pcap_len: b.data.len(),
                                timestamp: SystemTime::UNIX_EPOCH
                                    + std::time::Duration::from_micros(
                                        (b.ts_high as u64) << 32 | b.ts_low as u64,
                                    ),
                            }),
                            pcap_parser::Block::SimplePacket(b) => Some(PcapPointer {
                                idx,
                                pcap_offset: self.pcap_offset,
                                pcap_len: b.data.len(),
                                timestamp: SystemTime::now(), // Simple packets don't have a timestamp
                            }),
                            _ => None,
                        },
                        pcap_parser::PcapBlockOwned::Legacy(b) => Some(PcapPointer {
                            idx,
                            pcap_offset: self.pcap_offset,
                            pcap_len: b.data.len(),
                            timestamp: SystemTime::UNIX_EPOCH
                                + std::time::Duration::new(b.ts_sec as u64, b.ts_usec),
                        }),
                        _ => None,
                    };

                    self.pcap_reader.consume(current_offset);
                    self.pcap_offset += current_offset;
                    idx += 1;

                    if let Some(res) = res {
                        return Some(res);
                    }
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    self.pcap_reader.refill().unwrap();
                }
                Err(_) => break,
            }
        }

        return None;
    }
}

#[derive(Debug)]
pub struct UdpPacketInfo {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
}

#[derive(Debug)]
pub struct TcpPacketInfo {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

#[derive(Debug)]
pub enum PacketInfo {
    Udp(UdpPacketInfo),
    Tcp(TcpPacketInfo),
}

impl Display for PacketInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketInfo::Udp(udp) => write!(
                f,
                "{} → {} Len={}",
                udp.source_port,
                udp.destination_port,
                udp.length - 8
            ),
            PacketInfo::Tcp(tcp) => write!(
                f,
                "{} → {} Seq={} Ack={} Len={}",
                tcp.source_port,
                tcp.destination_port,
                tcp.sequence_number,
                tcp.acknowledgment_number,
                tcp.data_offset
            ),
        }
    }
}

#[derive(Debug)]
pub struct PcapPacket {
    pub idx: usize,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub info: PacketInfo,
    pub len: usize,
}

pub fn parse_packet(idx: usize, data: &[u8]) -> Option<PcapPacket> {
    let ethernet_packet = EthernetPacket::new(data)?;
    let (src_ip, dst_ip, protocol, info, len) = match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
            let (protocol, info) = match ipv4_packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                    let info = PacketInfo::Tcp(TcpPacketInfo {
                        source_port: tcp_packet.get_source(),
                        destination_port: tcp_packet.get_destination(),
                        sequence_number: tcp_packet.get_sequence(),
                        acknowledgment_number: tcp_packet.get_acknowledgement(),
                        data_offset: tcp_packet.get_data_offset(),
                        flags: tcp_packet.get_flags(),
                        window: tcp_packet.get_window(),
                        checksum: tcp_packet.get_checksum(),
                        urgent_ptr: tcp_packet.get_urgent_ptr(),
                    });
                    ("TCP".to_string(), info)
                }
                IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;
                    let info = PacketInfo::Udp(UdpPacketInfo {
                        source_port: udp_packet.get_source(),
                        destination_port: udp_packet.get_destination(),
                        length: udp_packet.get_length(),
                    });
                    ("UDP".to_string(), info)
                }
                _ => return None,
            };
            (
                ipv4_packet.get_source().to_string(),
                ipv4_packet.get_destination().to_string(),
                protocol,
                info,
                data.len(),
            )
        }
        EtherTypes::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new(ethernet_packet.payload())?;
            let (protocol, info) = match ipv6_packet.get_next_header() {
                pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                    let tcp_packet = TcpPacket::new(ipv6_packet.payload())?;
                    let info = PacketInfo::Tcp(TcpPacketInfo {
                        source_port: tcp_packet.get_source(),
                        destination_port: tcp_packet.get_destination(),
                        sequence_number: tcp_packet.get_sequence(),
                        acknowledgment_number: tcp_packet.get_acknowledgement(),
                        data_offset: tcp_packet.get_data_offset(),
                        flags: tcp_packet.get_flags(),
                        window: tcp_packet.get_window(),
                        checksum: tcp_packet.get_checksum(),
                        urgent_ptr: tcp_packet.get_urgent_ptr(),
                    });
                    ("TCP".to_string(), info)
                }
                pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                    let udp_packet = UdpPacket::new(ipv6_packet.payload())?;
                    let info = PacketInfo::Udp(UdpPacketInfo {
                        source_port: udp_packet.get_source(),
                        destination_port: udp_packet.get_destination(),
                        length: udp_packet.get_length(),
                    });
                    ("UDP".to_string(), info)
                }
                _ => return None,
            };
            (
                ipv6_packet.get_source().to_string(),
                ipv6_packet.get_destination().to_string(),
                protocol,
                info,
                data.len(),
            )
        }
        _ => return None,
    };

    Some(PcapPacket {
        idx,
        src_ip,
        dst_ip,
        protocol,
        info,
        len,
    })
}

pub fn parse_from_pcap_pointer(
    pcap_pointer: &PcapPointer,
    pcap_file: &Arc<Mutex<File>>,
) -> Option<PcapPacket> {
    let mut buffer = vec![0; pcap_pointer.pcap_len];
    {
        let mut reader = pcap_file.lock().unwrap();
        reader
            .seek(std::io::SeekFrom::Start(pcap_pointer.pcap_offset as u64))
            .unwrap();
        reader.read_exact(&mut buffer).unwrap();
    }
    parse_packet(pcap_pointer.idx, &buffer)
}
