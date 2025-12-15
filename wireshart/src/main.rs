mod l2;
mod l3;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the PCAPNG file
    #[arg(short, long)]
    pcap_path: String,
}

pub fn main() -> iced::Result {
    let args = Args::parse();
    let pcap_path = args.pcap_path;

    iced::application(
        move || l3::gui_main::MainGui::new(pcap_path.clone()),
        l3::gui_main::MainGui::update,
        l3::gui_main::MainGui::view,
    )
    .run()
}
