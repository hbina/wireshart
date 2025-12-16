use iced::futures::channel::mpsc;
use iced::futures::{SinkExt, Stream};
use iced::stream::try_channel;
use iced::widget::{button, column, row, scrollable, table, text};
use iced::Font;
use iced::{font, Length};
pub(crate) use packet_parser::{PcapPacket, PcapPointer, PcapPointerIterator};
use std::fs::File;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct MainGui {
    pcap_path: String,
    rows: Vec<PcapPacket>,
    pcap_file: Option<Arc<Mutex<File>>>,
}

impl MainGui {
    pub fn new(pcap_path: String) -> (Self, iced::Task<crate::l2::core::MainGuiMessage>) {
        let pcap_file = Some(Arc::new(Mutex::new(File::open(pcap_path.clone()).unwrap())));
        (
            Self {
                pcap_path,
                pcap_file,
                ..Self::default()
            },
            iced::Task::none(),
        )
    }

    pub fn update(
        &mut self,
        message: crate::l2::core::MainGuiMessage,
    ) -> iced::Task<crate::l2::core::MainGuiMessage> {
        match message {
            crate::l2::core::MainGuiMessage::Start => {
                let task = self.start();
                task.map(move |progress| crate::l2::core::MainGuiMessage::NewRow(progress))
            }
            crate::l2::core::MainGuiMessage::NewRow(progress) => {
                self.progress(progress);
                iced::Task::none()
            }
        }
    }

    pub fn start(&mut self) -> iced::Task<Result<PcapPointer, String>> {
        let (task, _) = iced::Task::stream(process_pcap_gui(self.pcap_path.clone())).abortable();
        task
    }

    pub fn progress(&mut self, new_progress: Result<PcapPointer, String>) {
        if let Ok(pcap_pointer) = new_progress {
            if let Some(packet) = packet_parser::parse_from_pcap_pointer(
                &pcap_pointer,
                self.pcap_file.as_ref().unwrap(),
            ) {
                self.rows.push(packet);
            }
        }
    }

    pub fn view(&self) -> iced::Element<'_, crate::l2::core::MainGuiMessage> {
        let bold = |header| {
            text(header).font(Font {
                weight: font::Weight::Bold,
                ..Font::DEFAULT
            })
        };

        if self.rows.is_empty() {
            return column![
                button("Start processing").on_press(crate::l2::core::MainGuiMessage::Start),
                text("No packets loaded yet.").size(20)
            ]
            .into();
        }

        column![
            row![text(format!("Processed {}", self.rows.len()))
                .size(20)
                .center()],
            scrollable(
                table(
                    [
                        table::column(
                            bold("No.").width(Length::Fixed(10f32)),
                            |packet: &PcapPacket| text(packet.idx)
                        )
                        .width(Length::Fixed(10f32)),
                        table::column(bold("Source IP"), |packet: &PcapPacket| {
                            text(&packet.src_ip)
                        }),
                        table::column(bold("Destination IP"), |packet: &PcapPacket| {
                            text(&packet.dst_ip)
                        }),
                        table::column(bold("Protocol"), |packet: &PcapPacket| {
                            text(&packet.protocol)
                        }),
                        table::column(bold("Length"), |packet: &PcapPacket| {
                            text(packet.len.to_string())
                        })
                        .width(Length::Fill),
                    ],
                    &self.rows
                )
                .width(Length::Fill)
            )
            .width(Length::Fill)
        ]
        .width(Length::Fill)
        .into()
    }
}

impl Default for MainGui {
    fn default() -> Self {
        Self {
            pcap_path: String::from(""), // Placeholder, will be replaced by user input
            rows: Vec::default(),
            pcap_file: None,
        }
    }
}

fn process_pcap_gui(file_path: String) -> impl Stream<Item = Result<PcapPointer, String>> {
    try_channel(1, move |mut output: mpsc::Sender<PcapPointer>| async move {
        for pcap in PcapPointerIterator::new(file_path) {
            if output.send(pcap).await.is_err() {
                break;
            }
        }

        Ok(())
    })
}
