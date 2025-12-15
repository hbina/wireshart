use iced::futures::channel::mpsc;
use iced::futures::{SinkExt, Stream};
use iced::stream::try_channel;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{PcapError, PcapNGReader};
use std::fs::File;
use std::sync::{Arc, Mutex};

const SCROLLABLE_ID: &str = "scrollable";

#[derive(Debug, Clone)]
pub struct PcapPointer {
    pub pcap_offset: usize,
    pub pcap_len: usize,
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
        loop {
            match self.pcap_reader.next() {
                Ok((current_offset, block)) => {
                    let res = match block {
                        pcap_parser::PcapBlockOwned::NG(ng) => match ng {
                            pcap_parser::Block::EnhancedPacket(b) => Some(PcapPointer {
                                pcap_offset: self.pcap_offset,
                                pcap_len: b.data.len(),
                            }),
                            pcap_parser::Block::SimplePacket(b) => Some(PcapPointer {
                                pcap_offset: self.pcap_offset,
                                pcap_len: b.data.len(),
                            }),
                            _ => None,
                        },
                        pcap_parser::PcapBlockOwned::Legacy(b) => Some(PcapPointer {
                            pcap_offset: self.pcap_offset,
                            pcap_len: b.data.len(),
                        }),
                        _ => None,
                    };

                    self.pcap_reader.consume(current_offset);
                    self.pcap_offset += current_offset;

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
pub struct MainGui {
    pcap_path: String,
    rows: Vec<PcapPointer>,
    expanded: std::collections::HashSet<usize>,
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
            crate::l2::core::MainGuiMessage::Expand(idx) => {
                self.expanded.insert(idx);
                iced::Task::none()
            }
            crate::l2::core::MainGuiMessage::Collapse(idx) => {
                self.expanded.remove(&idx);
                iced::Task::none()
            }
        }
    }

    pub fn start(&mut self) -> iced::Task<Result<PcapPointer, String>> {
        let (task, _) = iced::Task::stream(process_pcap_gui(self.pcap_path.clone())).abortable();
        task
    }

    pub fn progress(&mut self, new_progress: Result<PcapPointer, String>) {
        let new_progress = new_progress.unwrap();
        // println!("idx:{} offset:{}", self.rows.len(), new_progress.offset);
        self.rows.push(new_progress);
    }

    pub fn view(&self) -> iced::Element<'_, crate::l2::core::MainGuiMessage> {
        // let rows = Column::with_children(
        //     self.rows
        //         .iter()
        //         .map(|s: &usize| text!("Block size {s}").into()),
        // );

        let scrollable = iced::widget::scrollable(iced::widget::Column::with_children(
            self.rows.iter().enumerate().map(|(idx, r)| {
                super::gui_pcap::create_pcap_block_widget(
                    idx,
                    self.expanded.contains(&idx),
                    r,
                    self.pcap_file.as_ref().unwrap(),
                )
                .into()
            }),
        ))
        .direction(iced::widget::scrollable::Direction::Vertical(
            iced::widget::scrollable::Scrollbar::new(),
        ))
        .width(iced::Fill)
        .height(iced::Fill)
        .id(SCROLLABLE_ID);

        let control: iced::Element<_> = iced::widget::button("Start processing")
            .on_press(crate::l2::core::MainGuiMessage::Start)
            .into();

        iced::widget::Column::new()
            .push(control)
            .push(scrollable)
            .into()
    }
}

impl Default for MainGui {
    fn default() -> Self {
        Self {
            pcap_path: String::from(""), // Placeholder, will be replaced by user input
            rows: Vec::default(),
            expanded: std::collections::HashSet::default(),
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
