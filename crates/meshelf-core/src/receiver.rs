use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("clipboard error: {message}")]
pub struct ClipboardError {
    message: String,
}

impl ClipboardError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

pub trait ClipboardSink: Send + Sync + 'static {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError>;
}
