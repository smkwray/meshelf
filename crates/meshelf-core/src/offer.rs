use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::MAX_TEXT_BYTES;

pub const MAX_OFFER_PREVIEW_BYTES: usize = 256;
pub const MAX_OFFER_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_OFFER_TRANSFER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_OFFER_MANIFEST_ENTRIES: u32 = 4096;
pub const MAX_OFFER_PORTABLE_COMPONENT_BYTES: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OfferId(Uuid);

impl OfferId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for OfferId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OfferId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for OfferId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardAvailability {
    Available,
    SourceUnavailable,
    SourceChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OfferDescriptor {
    Text {
        utf8_bytes: u32,
        line_count: u32,
        preview: String,
    },
    File {
        root_name: String,
        total_bytes: u64,
    },
    Folder {
        root_name: String,
        total_bytes: u64,
        entry_count: u32,
        file_count: u32,
        directory_count: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OfferDescriptorError {
    #[error("text is empty")]
    EmptyText,
    #[error("text is {bytes} bytes; maximum is {maximum}")]
    TextTooLarge { bytes: usize, maximum: usize },
    #[error("text byte count cannot be represented as u32")]
    TextByteCountOverflow,
    #[error("text line count cannot be represented as u32")]
    LineCountOverflow,
    #[error("text descriptor has zero lines")]
    EmptyLineCount,
    #[error("text preview is {bytes} bytes; maximum is {maximum}")]
    PreviewTooLarge { bytes: usize, maximum: usize },
    #[error("text preview contains a control character")]
    PreviewContainsControl,
    #[error("root name is empty")]
    EmptyRootName,
    #[error("root name is a path rather than a basename")]
    RootNameIsPath,
    #[error("root name contains a control character")]
    RootNameContainsControl,
    #[error("root name is {bytes} bytes; maximum is {maximum}")]
    RootNameTooLarge { bytes: usize, maximum: usize },
    #[error("file is {bytes} bytes; maximum is {maximum}")]
    FileTooLarge { bytes: u64, maximum: u64 },
    #[error("transfer is {bytes} bytes; maximum is {maximum}")]
    TransferTooLarge { bytes: u64, maximum: u64 },
    #[error("folder has {entries} entries; maximum is {maximum}")]
    TooManyEntries { entries: u32, maximum: u32 },
    #[error(
        "folder entry count {entries} does not equal file count {files} plus directory count {directories}"
    )]
    EntryCountMismatch {
        entries: u32,
        files: u32,
        directories: u32,
    },
}

impl OfferDescriptor {
    /// Creates a text descriptor from the text captured at the explicit paste action.
    pub fn text(text: impl AsRef<str>) -> Result<Self, OfferDescriptorError> {
        let text = text.as_ref();
        let utf8_bytes = text.len();
        if utf8_bytes == 0 {
            return Err(OfferDescriptorError::EmptyText);
        }
        if utf8_bytes > MAX_TEXT_BYTES {
            return Err(OfferDescriptorError::TextTooLarge {
                bytes: utf8_bytes,
                maximum: MAX_TEXT_BYTES,
            });
        }
        let line_count = text.lines().count();
        let line_count =
            u32::try_from(line_count).map_err(|_| OfferDescriptorError::LineCountOverflow)?;
        let utf8_bytes =
            u32::try_from(utf8_bytes).map_err(|_| OfferDescriptorError::TextByteCountOverflow)?;
        let descriptor = Self::Text {
            utf8_bytes,
            line_count,
            preview: Self::preview(text),
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Builds the bounded, display-only preview for a text descriptor.
    ///
    /// This is the only implementation of the preview bound and normalization rule.
    #[must_use]
    pub fn preview(text: &str) -> String {
        let mut normalized = String::with_capacity(text.len().min(MAX_OFFER_PREVIEW_BYTES));
        for character in text.chars() {
            if matches!(character, '\n' | '\r') {
                if !normalized.ends_with(' ') {
                    normalized.push(' ');
                }
            } else if !character.is_control() {
                normalized.push(character);
            }
        }

        let mut end = normalized.len().min(MAX_OFFER_PREVIEW_BYTES);
        while !normalized.is_char_boundary(end) {
            end -= 1;
        }
        normalized.truncate(end);
        normalized
    }

    pub fn validate(&self) -> Result<(), OfferDescriptorError> {
        match self {
            Self::Text {
                utf8_bytes,
                line_count,
                preview,
            } => {
                if *utf8_bytes == 0 {
                    return Err(OfferDescriptorError::EmptyText);
                }
                if usize::try_from(*utf8_bytes).unwrap_or(usize::MAX) > MAX_TEXT_BYTES {
                    return Err(OfferDescriptorError::TextTooLarge {
                        bytes: usize::try_from(*utf8_bytes).unwrap_or(usize::MAX),
                        maximum: MAX_TEXT_BYTES,
                    });
                }
                if *line_count == 0 {
                    return Err(OfferDescriptorError::EmptyLineCount);
                }
                if preview.len() > MAX_OFFER_PREVIEW_BYTES {
                    return Err(OfferDescriptorError::PreviewTooLarge {
                        bytes: preview.len(),
                        maximum: MAX_OFFER_PREVIEW_BYTES,
                    });
                }
                if preview.chars().any(char::is_control) {
                    return Err(OfferDescriptorError::PreviewContainsControl);
                }
            }
            Self::File {
                root_name,
                total_bytes,
            } => {
                validate_root_name(root_name)?;
                if *total_bytes > MAX_OFFER_FILE_BYTES {
                    return Err(OfferDescriptorError::FileTooLarge {
                        bytes: *total_bytes,
                        maximum: MAX_OFFER_FILE_BYTES,
                    });
                }
            }
            Self::Folder {
                root_name,
                total_bytes,
                entry_count,
                file_count,
                directory_count,
            } => {
                validate_root_name(root_name)?;
                if *entry_count > MAX_OFFER_MANIFEST_ENTRIES {
                    return Err(OfferDescriptorError::TooManyEntries {
                        entries: *entry_count,
                        maximum: MAX_OFFER_MANIFEST_ENTRIES,
                    });
                }
                if *total_bytes > MAX_OFFER_TRANSFER_BYTES {
                    return Err(OfferDescriptorError::TransferTooLarge {
                        bytes: *total_bytes,
                        maximum: MAX_OFFER_TRANSFER_BYTES,
                    });
                }
                if file_count.checked_add(*directory_count) != Some(*entry_count) {
                    return Err(OfferDescriptorError::EntryCountMismatch {
                        entries: *entry_count,
                        files: *file_count,
                        directories: *directory_count,
                    });
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_text(&self) -> bool {
        matches!(self, Self::Text { .. })
    }
}

fn validate_root_name(root_name: &str) -> Result<(), OfferDescriptorError> {
    if root_name.is_empty() {
        return Err(OfferDescriptorError::EmptyRootName);
    }
    if root_name == "." || root_name == ".." || root_name.contains('/') || root_name.contains('\\')
    {
        return Err(OfferDescriptorError::RootNameIsPath);
    }
    if root_name.chars().any(char::is_control) {
        return Err(OfferDescriptorError::RootNameContainsControl);
    }
    if root_name.len() > MAX_OFFER_PORTABLE_COMPONENT_BYTES {
        return Err(OfferDescriptorError::RootNameTooLarge {
            bytes: root_name.len(),
            maximum: MAX_OFFER_PORTABLE_COMPONENT_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_descriptor_rejects_zero_and_over_one_mib() {
        assert!(matches!(
            OfferDescriptor::text(""),
            Err(OfferDescriptorError::EmptyText)
        ));
        let oversized = "a".repeat(MAX_TEXT_BYTES + 1);
        assert!(matches!(
            OfferDescriptor::text(oversized),
            Err(OfferDescriptorError::TextTooLarge { .. })
        ));
    }

    #[test]
    fn text_preview_is_bounded_and_truncates_on_a_character_boundary() {
        let input = format!("{}🙂tail\n\u{0007}end", "a".repeat(254));
        let OfferDescriptor::Text { preview, .. } = OfferDescriptor::text(input).expect("text")
        else {
            panic!("expected text descriptor");
        };
        assert!(preview.len() <= MAX_OFFER_PREVIEW_BYTES);
        assert!(preview.is_char_boundary(preview.len()));
        assert!(!preview.contains('\n'));
        assert!(!preview.contains('\u{0007}'));
        assert_eq!(preview, "a".repeat(254));
    }

    #[test]
    fn folder_descriptor_enforces_entry_and_transfer_bounds() {
        let too_many = OfferDescriptor::Folder {
            root_name: "folder".to_owned(),
            total_bytes: 0,
            entry_count: MAX_OFFER_MANIFEST_ENTRIES + 1,
            file_count: MAX_OFFER_MANIFEST_ENTRIES + 1,
            directory_count: 0,
        };
        assert!(matches!(
            too_many.validate(),
            Err(OfferDescriptorError::TooManyEntries { .. })
        ));

        let too_large = OfferDescriptor::Folder {
            root_name: "folder".to_owned(),
            total_bytes: MAX_OFFER_TRANSFER_BYTES + 1,
            entry_count: 0,
            file_count: 0,
            directory_count: 0,
        };
        assert!(matches!(
            too_large.validate(),
            Err(OfferDescriptorError::TransferTooLarge { .. })
        ));
    }

    #[test]
    fn zero_byte_file_is_valid_not_missing_input() {
        let descriptor = OfferDescriptor::File {
            root_name: "empty.txt".to_owned(),
            total_bytes: 0,
        };
        assert_eq!(descriptor.validate(), Ok(()));
    }
}
