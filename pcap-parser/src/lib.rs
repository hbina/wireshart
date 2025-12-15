#[cfg(feature = "gui")]
use iced::futures::channel::mpsc;
#[cfg(feature = "gui")]
use iced::futures::{SinkExt, Stream};
#[cfg(feature = "gui")]
use iced::stream::try_channel;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{PcapError, PcapNGReader};

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

#[cfg(feature = "gui")]
pub fn process_pcap_gui(file_path: String) -> impl Stream<Item = Result<PcapPointer, String>> {
    try_channel(1, move |mut output: mpsc::Sender<PcapPointer>| async move {
        for pcap in PcapPointerIterator::new(file_path) {
            output.send(pcap).await.unwrap();
        }

        Ok(())
    })
}
