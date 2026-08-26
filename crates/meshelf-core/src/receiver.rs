use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("clipboard error: {message}")]
pub struct ClipboardError {
    message: String,
    uncertain: bool,
}

impl ClipboardError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            uncertain: false,
        }
    }

    #[must_use]
    pub fn uncertain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            uncertain: true,
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn is_uncertain(&self) -> bool {
        self.uncertain
    }
}

pub trait ClipboardSink: Send + Sync + 'static {
    fn set_text(&self, text: &str) -> Result<(), ClipboardError>;
}
