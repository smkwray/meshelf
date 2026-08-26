//! Cheap, metadata-only preparation for a durable v2 offer source.

use std::{
    fs::{self, Metadata},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use meshelf_core::{
    MAX_OFFER_FILE_BYTES, MAX_OFFER_MANIFEST_ENTRIES, MAX_OFFER_TRANSFER_BYTES, OfferDescriptor,
    OfferSource,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferInput {
    Text(String),
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOfferSource {
    pub descriptor: OfferDescriptor,
    pub source: OfferSource,
}

pub type PreparedSource = PreparedOfferSource;

#[derive(Debug, Error)]
pub enum SourcePreparationError {
    #[error("text offer is invalid: {0}")]
    Text(#[from] meshelf_core::OfferDescriptorError),
    #[error("source path could not be inspected")]
    Inspect(#[source] std::io::Error),
    #[error("source path is a symbolic link")]
    Symlink,
    #[error("source path is not a regular file or directory")]
    SpecialFile,
    #[error("source name is not valid UTF-8")]
    NonUtf8Name,
    #[error("source name is not portable")]
    InvalidName,
    #[error("source file exceeds the v2 size limit")]
    FileTooLarge,
    #[error("source tree exceeds the v2 size or entry limit")]
    TreeTooLarge,
    #[error("source metadata commitment failed")]
    Commitment,
}

pub fn prepare_source(input: OfferInput) -> Result<PreparedOfferSource, SourcePreparationError> {
    match input {
        OfferInput::Text(text) => {
            let descriptor = OfferDescriptor::text(&text)?;
            Ok(PreparedOfferSource {
                descriptor,
                source: OfferSource::Text { text },
            })
        }
        OfferInput::Path(path) => prepare_path(&path),
    }
}

fn prepare_path(path: &Path) -> Result<PreparedOfferSource, SourcePreparationError> {
    let initial_metadata = fs::symlink_metadata(path).map_err(SourcePreparationError::Inspect)?;
    if initial_metadata.file_type().is_symlink() {
        return Err(SourcePreparationError::Symlink);
    }

    // This is deliberately the only canonicalize call. Descendants are
    // inspected by metadata at their canonical-root-relative paths.
    let canonical_path = fs::canonicalize(path).map_err(SourcePreparationError::Inspect)?;
    let metadata =
        fs::symlink_metadata(&canonical_path).map_err(SourcePreparationError::Inspect)?;
    if metadata.file_type().is_symlink() {
        return Err(SourcePreparationError::Symlink);
    }
    let root_name = portable_name(&canonical_path)?;
    validate_component(&root_name)?;

    let mut commitment = Sha256::new();
    hash_metadata(&mut commitment, "root", &root_name, &metadata)?;
    if metadata.is_file() {
        let total_bytes = metadata.len();
        if total_bytes > MAX_OFFER_FILE_BYTES {
            return Err(SourcePreparationError::FileTooLarge);
        }
        let descriptor = OfferDescriptor::File {
            root_name,
            total_bytes,
        };
        descriptor.validate()?;
        return Ok(PreparedOfferSource {
            descriptor,
            source: OfferSource::File {
                canonical_path,
                metadata_commitment: commitment.finalize().to_vec(),
            },
        });
    }
    if !metadata.is_dir() {
        return Err(SourcePreparationError::SpecialFile);
    }

    let mut stats = TreeStats::default();
    walk_directory(&canonical_path, Path::new(""), &mut commitment, &mut stats)?;
    let descriptor = OfferDescriptor::Folder {
        root_name,
        total_bytes: stats.total_bytes,
        entry_count: stats.entry_count,
        file_count: stats.file_count,
        directory_count: stats.directory_count,
    };
    descriptor.validate()?;
    Ok(PreparedOfferSource {
        descriptor,
        source: OfferSource::Folder {
            canonical_path,
            metadata_commitment: commitment.finalize().to_vec(),
        },
    })
}

#[derive(Debug, Default)]
struct TreeStats {
    total_bytes: u64,
    entry_count: u32,
    file_count: u32,
    directory_count: u32,
}

fn walk_directory(
    directory: &Path,
    relative_directory: &Path,
    commitment: &mut Sha256,
    stats: &mut TreeStats,
) -> Result<(), SourcePreparationError> {
    let mut children = fs::read_dir(directory)
        .map_err(SourcePreparationError::Inspect)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(SourcePreparationError::Inspect)?;
    children.sort_by_key(|left| left.file_name());

    for child in children {
        let name = child
            .file_name()
            .to_str()
            .ok_or(SourcePreparationError::NonUtf8Name)?
            .to_owned();
        validate_component(&name)?;
        let relative = relative_directory.join(&name);
        let metadata =
            fs::symlink_metadata(child.path()).map_err(SourcePreparationError::Inspect)?;
        if metadata.file_type().is_symlink() {
            return Err(SourcePreparationError::Symlink);
        }
        stats.entry_count = stats
            .entry_count
            .checked_add(1)
            .ok_or(SourcePreparationError::TreeTooLarge)?;
        if stats.entry_count > MAX_OFFER_MANIFEST_ENTRIES {
            return Err(SourcePreparationError::TreeTooLarge);
        }
        let relative_name = portable_relative_name(&relative)?;
        hash_metadata(commitment, "entry", &relative_name, &metadata)?;
        if metadata.is_file() {
            stats.file_count = stats
                .file_count
                .checked_add(1)
                .ok_or(SourcePreparationError::TreeTooLarge)?;
            stats.total_bytes = stats
                .total_bytes
                .checked_add(metadata.len())
                .ok_or(SourcePreparationError::TreeTooLarge)?;
            if metadata.len() > MAX_OFFER_FILE_BYTES || stats.total_bytes > MAX_OFFER_TRANSFER_BYTES
            {
                return Err(SourcePreparationError::TreeTooLarge);
            }
        } else if metadata.is_dir() {
            stats.directory_count = stats
                .directory_count
                .checked_add(1)
                .ok_or(SourcePreparationError::TreeTooLarge)?;
            walk_directory(&child.path(), &relative, commitment, stats)?;
        } else {
            return Err(SourcePreparationError::SpecialFile);
        }
    }
    Ok(())
}

fn portable_name(path: &Path) -> Result<String, SourcePreparationError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .ok_or(SourcePreparationError::NonUtf8Name)
}

fn portable_relative_name(path: &Path) -> Result<String, SourcePreparationError> {
    path.components()
        .map(|component| {
            let name = component
                .as_os_str()
                .to_str()
                .ok_or(SourcePreparationError::NonUtf8Name)?;
            validate_component(name)?;
            Ok(name.to_owned())
        })
        .collect::<Result<Vec<_>, SourcePreparationError>>()
        .map(|parts| parts.join("/"))
}

fn validate_component(component: &str) -> Result<(), SourcePreparationError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.ends_with(' ')
        || component.ends_with('.')
        || component
            .chars()
            .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
    {
        return Err(SourcePreparationError::InvalidName);
    }
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
    {
        return Err(SourcePreparationError::InvalidName);
    }
    Ok(())
}

fn hash_metadata(
    hasher: &mut Sha256,
    kind: &str,
    relative_name: &str,
    metadata: &Metadata,
) -> Result<(), SourcePreparationError> {
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(relative_name.as_bytes());
    hasher.update([0]);
    hash_metadata_identity(hasher, metadata);
    hasher.update(metadata.len().to_le_bytes());
    hasher.update([u8::from(metadata.is_file()), u8::from(metadata.is_dir())]);
    hasher.update([u8::from(metadata.permissions().readonly())]);
    let modified = metadata
        .modified()
        .map_err(|_| SourcePreparationError::Commitment)?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SourcePreparationError::Commitment)?;
    hasher.update(modified.as_secs().to_le_bytes());
    hasher.update(modified.subsec_nanos().to_le_bytes());
    Ok(())
}

/// Include a stable object identity where the host exposes one. Unix uses the
/// device/inode pair; Windows uses the volume serial and file index. The
/// fallback still binds the metadata commitment to the portable fields below,
/// but does not invent a Unix-only identity for another platform.
fn hash_metadata_identity(hasher: &mut Sha256, metadata: &Metadata) {
    hasher.update(meshelf_platform::source_identity_bytes(metadata));
}

#[cfg(test)]
mod tests {
    use std::fs;

    use meshelf_core::{MAX_OFFER_PREVIEW_BYTES, OfferDescriptor, OfferSource};
    use tempfile::tempdir;

    use super::{OfferInput, prepare_source};

    #[test]
    fn text_offer_persists_exact_body_and_bounded_preview() {
        let text = format!("{}🙂\n\u{0007}tail", "a".repeat(300));
        let prepared = prepare_source(OfferInput::Text(text.clone())).expect("text source");
        let OfferSource::Text { text: stored } = &prepared.source else {
            panic!("expected text source");
        };
        assert_eq!(stored, &text);
        let OfferDescriptor::Text { preview, .. } = prepared.descriptor else {
            panic!("expected text descriptor");
        };
        assert!(preview.len() <= MAX_OFFER_PREVIEW_BYTES);
        assert!(!preview.contains('\n'));
        assert!(!preview.contains('\u{0007}'));
    }

    #[test]
    fn file_offer_retains_canonical_path_without_payload() {
        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("file.txt");
        fs::write(&file, b"payload that is not retained").expect("write file");
        let prepared = prepare_source(OfferInput::Path(file.clone())).expect("file source");
        let OfferSource::File {
            canonical_path,
            metadata_commitment,
        } = prepared.source
        else {
            panic!("expected file source");
        };
        assert_eq!(
            canonical_path,
            fs::canonicalize(file).expect("canonical path")
        );
        assert_eq!(metadata_commitment.len(), 32);
    }

    #[test]
    fn folder_offer_retains_no_manifest() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("folder");
        fs::create_dir_all(root.join("nested")).expect("create folder");
        fs::write(root.join("nested").join("item.txt"), b"body").expect("write file");
        let prepared = prepare_source(OfferInput::Path(root.clone())).expect("folder source");
        let OfferSource::Folder {
            canonical_path,
            metadata_commitment,
        } = prepared.source
        else {
            panic!("expected folder source");
        };
        assert_eq!(
            canonical_path,
            fs::canonicalize(root).expect("canonical path")
        );
        assert_eq!(metadata_commitment.len(), 32);
        assert!(matches!(
            prepared.descriptor,
            OfferDescriptor::Folder { .. }
        ));
    }

    /// Symlink and special-file rejection is only exercised on Unix: creating a symlink on Windows
    /// needs privilege or Developer Mode, so a Windows test here would fail on an ordinary machine
    /// and make the gate flaky. Windows reparse points therefore have NO coverage at this layer.
    /// The receiver-side validation in Step 7 is where that gap has to be closed.
    #[cfg(unix)]
    #[test]
    fn source_preparation_rejects_symlink_and_special_file() {
        use std::process::Command;

        use super::SourcePreparationError;

        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("file");
        fs::write(&file, b"body").expect("write file");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        assert!(matches!(
            prepare_source(OfferInput::Path(link)),
            Err(SourcePreparationError::Symlink)
        ));

        let fifo = directory.path().join("fifo");
        let status = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo is available on Unix");
        assert!(status.success(), "mkfifo failed: {status}");
        assert!(matches!(
            prepare_source(OfferInput::Path(fifo.clone())),
            Err(SourcePreparationError::SpecialFile)
        ));
        fs::remove_file(fifo).expect("remove fifo");
    }

    #[test]
    fn source_preparation_does_not_read_regular_file_bodies() {
        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("metadata-only");
        fs::write(&file, b"body").expect("write file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o000))
                .expect("remove body-read permission");
        }
        let prepared = prepare_source(OfferInput::Path(file)).expect("metadata-only source");
        assert!(matches!(prepared.source, OfferSource::File { .. }));
    }

    #[test]
    fn classifies_text_and_future_file_items() {
        let directory = tempdir().expect("temporary directory");
        let file = directory.path().join("example.txt");
        fs::write(&file, "example").expect("write example file");

        assert!(matches!(
            prepare_source(OfferInput::Text("ordinary text".to_owned()))
                .expect("text source")
                .source,
            OfferSource::Text { .. }
        ));
        assert!(matches!(
            prepare_source(OfferInput::Path(file))
                .expect("file source")
                .source,
            OfferSource::File { .. }
        ));
        assert!(matches!(
            prepare_source(OfferInput::Path(directory.path().to_owned()))
                .expect("folder source")
                .source,
            OfferSource::Folder { .. }
        ));
        assert!(matches!(
            prepare_source(OfferInput::Text("C:\\future\\item.txt".to_owned()))
                .expect("future path-looking text")
                .source,
            OfferSource::Text { .. }
        ));
    }

    #[test]
    fn prepares_nested_folder_manifest_in_stable_order() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("package");
        fs::create_dir_all(root.join("empty")).expect("create empty folder");
        fs::create_dir_all(root.join("nested")).expect("create nested folder");
        fs::write(root.join("b.txt"), "bravo").expect("write b");
        fs::write(root.join("nested").join("a.txt"), "alpha").expect("write a");

        let prepared = prepare_source(OfferInput::Path(root)).expect("prepare folder");
        assert_eq!(
            prepared.descriptor,
            OfferDescriptor::Folder {
                root_name: "package".to_owned(),
                total_bytes: 10,
                entry_count: 4,
                file_count: 2,
                directory_count: 2,
            }
        );
        assert!(matches!(prepared.source, OfferSource::Folder { .. }));
    }
}
