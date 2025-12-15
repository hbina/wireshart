use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::fmt::{Display, Formatter};

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
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub info: PacketInfo,
    pub len: usize,
}

pub fn parse_packet(data: &[u8]) -> Option<PcapPacket> {
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
        src_ip,
        dst_ip,
        protocol,
        info,
        len,
    })
}
