use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

#[derive(Debug)]
pub struct PcapPacket {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub info: String,
    pub len: usize,
}

pub fn parse_packet(data: &[u8]) -> Option<PcapPacket> {
    let ethernet_packet = EthernetPacket::new(data)?;
    let (src_ip, dst_ip, protocol, info, len) = match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
            let (protocol, info) = match ipv4_packet.get_next_level_protocol().to_string().to_uppercase().as_str() {
                "TCP" => {
                    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
                    let info = format!(
                        "{} → {} Len={}",
                        tcp_packet.get_source(),
                        tcp_packet.get_destination(),
                        ipv4_packet.payload().len() - tcp_packet.get_data_offset() as usize * 4
                    );
                    ("TCP".to_string(), info)
                }
                "UDP" => {
                    let udp_packet = UdpPacket::new(ipv4_packet.payload())?;
                    let info = format!(
                        "{} → {} Len={}",
                        udp_packet.get_source(),
                        udp_packet.get_destination(),
                        udp_packet.get_length() - 8
                    );
                    ("UDP".to_string(), info)
                }
                _ => ("".to_string(), "".to_string()),
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
            // Parsing for TCP/UDP over IPv6 can be added here
            (
                ipv6_packet.get_source().to_string(),
                ipv6_packet.get_destination().to_string(),
                ipv6_packet.get_next_header().to_string().to_uppercase(),
                "".to_string(),
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