use std::fs::File;
use std::io::{Read, Seek};
use std::sync::{Arc, Mutex};

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
            .seek(std::io::SeekFrom::Start(r.pcap_offset as u64 + 16))
            .unwrap();
        reader.read(&mut buffer).unwrap();
    };

    // Ethernet
    let start_offset = 0;
    let end_offset = start_offset + etherparse::Ethernet2Header::LEN;

    let ethernet_header =
        match etherparse::Ethernet2HeaderSlice::from_slice(&buffer[start_offset..end_offset]) {
            Ok(ok) => ok,
            Err(err) => {
                return iced::Element::new(iced::widget::column![
                    iced::widget::button("Collapse")
                        .on_press(crate::l2::core::MainGuiMessage::Collapse(idx)),
                    iced::widget::text!("{} {}", idx, r.pcap_offset),
                    iced::widget::text!("{:?}", err),
                ]);
            }
        };

    // IPV4

    let start_offset = end_offset;
    let end_offset = start_offset + etherparse::Ipv4Header::MIN_LEN;

    let ipv4_header =
        match etherparse::Ipv4HeaderSlice::from_slice(&buffer[start_offset..end_offset]) {
            Ok(ok) => ok,
            Err(err) => {
                return iced::Element::new(iced::widget::column![
                    iced::widget::button("Collapse")
                        .on_press(crate::l2::core::MainGuiMessage::Collapse(idx)),
                    iced::widget::text!("{} {}", idx, r.pcap_offset),
                    iced::widget::text!("{:?}", ethernet_header),
                    iced::widget::text!("{:?}", err),
                ]);
            }
        };

    let end_offset = end_offset + ipv4_header.options().len();

    // UDP

    let start_offset = end_offset;
    let end_offset = start_offset + etherparse::UdpHeader::LEN;

    let udp_header = match etherparse::UdpHeaderSlice::from_slice(&buffer[start_offset..end_offset])
    {
        Ok(ok) => ok,
        Err(err) => {
            return iced::Element::new(iced::widget::column![
                iced::widget::button("Collapse")
                    .on_press(crate::l2::core::MainGuiMessage::Collapse(idx)),
                iced::widget::text!("{} {}", idx, r.pcap_offset),
                iced::widget::text!("{:?}", ethernet_header),
                iced::widget::text!("{:?}", ipv4_header),
                iced::widget::text!("{:?}", err),
            ]);
        }
    };

    // rows

    iced::Element::new(iced::widget::column![
        iced::widget::button("Collapse").on_press(crate::l2::core::MainGuiMessage::Collapse(idx)),
        iced::widget::text!("{} {}", idx, r.pcap_offset),
        iced::widget::text!("{:?}", ethernet_header),
        iced::widget::text!("{:?}", ipv4_header),
        iced::widget::text!("{:?}", udp_header)
    ])
}

pub fn create_pcap_block_widget<'a>(
    idx: usize,
    expanded: bool,
    r: &super::gui_main::PcapPointer,
    pcap_file: &Arc<Mutex<File>>,
) -> iced::Element<'a, crate::l2::core::MainGuiMessage> {
    if expanded {
        create_pcap_block_widget_expanded(idx, r, pcap_file)
    } else {
        create_pcap_block_widget_collapsed(idx, r)
    }
}
