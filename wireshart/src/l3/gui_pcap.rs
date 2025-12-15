use std::fs::File;
use std::io::{Read, Seek};
use std::sync::{Arc, Mutex};
use packet_parser::PacketInfo;

fn create_pcap_block_widget_collapsed<'a>(
    idx: usize,
    r: &super::gui_main::PcapPointer,
) -> iced::Element<'a, crate::l2::core::MainGuiMessage> {
    iced::Element::new(iced::widget::column![
        iced::widget::button("Expand").on_press(crate::l2::core::MainGuiMessage::Expand(idx)),
        iced::widget::text!("{} {}", idx, r.pcap_offset)
    ])
}

fn create_pcap_block_widget_expanded<'a>(
    idx: usize,
    r: &super::gui_main::PcapPointer,
    pcap_file: &Arc<Mutex<File>>,
) -> iced::Element<'a, crate::l2::core::MainGuiMessage> {
    let mut buffer = vec![0; r.pcap_len];
    {
        let mut reader = pcap_file.lock().unwrap();
        reader
            .seek(std::io::SeekFrom::Start(r.pcap_offset as u64))
            .unwrap();
        reader.read_exact(&mut buffer).unwrap();
    };

    let parsed_packet = match packet_parser::parse_packet(&buffer) {
        Some(packet) => packet,
        None => {
            return iced::Element::new(iced::widget::column![
                iced::widget::button("Collapse")
                    .on_press(crate::l2::core::MainGuiMessage::Collapse(idx)),
                iced::widget::text!("{} {}", idx, r.pcap_offset),
                iced::widget::text!("Failed to parse packet"),
            ]);
        }
    };

    let mut info_widget = iced::widget::column![
        iced::widget::text!("Source IP: {}", parsed_packet.src_ip),
        iced::widget::text!("Destination IP: {}", parsed_packet.dst_ip),
        iced::widget::text!("Protocol: {}", parsed_packet.protocol),
    ];

    match parsed_packet.info {
        PacketInfo::Udp(udp) => {
            info_widget = info_widget.push(iced::widget::text!("Source Port: {}", udp.source_port));
            info_widget = info_widget.push(iced::widget::text!("Destination Port: {}", udp.destination_port));
            info_widget = info_widget.push(iced::widget::text!("Length: {}", udp.length));
        }
        PacketInfo::Tcp(tcp) => {
            info_widget = info_widget.push(iced::widget::text!("Source Port: {}", tcp.source_port));
            info_widget = info_widget.push(iced::widget::text!("Destination Port: {}", tcp.destination_port));
            info_widget = info_widget.push(iced::widget::text!("Sequence Number: {}", tcp.sequence_number));
            info_widget = info_widget.push(iced::widget::text!("Acknowledgment Number: {}", tcp.acknowledgment_number));
            info_widget = info_widget.push(iced::widget::text!("Data Offset: {}", tcp.data_offset));
            info_widget = info_widget.push(iced::widget::text!("Flags: {}", tcp.flags));
            info_widget = info_widget.push(iced::widget::text!("Window: {}", tcp.window));
            info_widget = info_widget.push(iced::widget::text!("Checksum: {}", tcp.checksum));
            info_widget = info_widget.push(iced::widget::text!("Urgent Pointer: {}", tcp.urgent_ptr));
        }
    }

    iced::Element::new(iced::widget::column![
        iced::widget::button("Collapse").on_press(crate::l2::core::MainGuiMessage::Collapse(idx)),
        iced::widget::text!("{} {}", idx, r.pcap_offset),
        info_widget,
    ])
}

pub fn create_pcap_block_widget<'a>(
    idx: usize,
    expanded: bool,
    r: &super::gui_main::PcapPointer,
    pcap_file: &Arc<Mutex<File>>,
) -> iced::Element<'a, crate::l2::core::MainGuiMessage> {
    if expanded {
        return create_pcap_block_widget_expanded(idx, r, pcap_file);
    } else {
        return create_pcap_block_widget_collapsed(idx, r);
    }
}
