#[derive(Debug, Clone)]
pub enum MainGuiMessage {
    Start,
    NewRow(Result<crate::l3::gui_main::PcapPointer, String>),
}
