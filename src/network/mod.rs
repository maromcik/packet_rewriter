pub mod error;
pub mod parse;
pub mod rewrite;

pub struct CaptureConfig {
    pub capture_device: String,
    pub output_device: String,
    pub filter: Option<String>,

}