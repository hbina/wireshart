use iced::futures::channel::mpsc;
use iced::futures::{SinkExt, Stream};
use iced::stream::try_channel;
pub(crate) use packet_parser::{PcapPointer, PcapPointerIterator};
use std::fs::File;
use std::sync::{Arc, Mutex};

const SCROLLABLE_ID: &str = "scrollable";

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
