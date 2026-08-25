//! Shared destination publication orchestration for v1 and pull-v2.
//!
//! The receiver workflows remain separate, but every final file/folder publication uses this
//! collision-safe kernel.  Platform-specific rename and Windows path spelling stay behind
//! `meshelf-platform`.

use std::path::{Path, PathBuf};

use meshelf_core::{ContentKind, MAX_OFFER_PORTABLE_COMPONENT_BYTES, validate_component};
use meshelf_platform::{reject_reparse_point, rename_exclusive_portable};

use crate::NetError;

pub(crate) async fn finalize_payload_without_overwrite(
    payload: &Path,
    directory: &Path,
    root_name: &str,
    content_kind: ContentKind,
) -> Result<PathBuf, NetError> {
    meshelf_platform::require_directory(directory)?;
    for index in 1..=9999 {
        let final_path = collision_candidate(directory, root_name, content_kind, index)?;
        match finalize_payload(payload, &final_path, content_kind).await {
            Ok(()) => return Ok(final_path),
            Err(NetError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    let suffix = format!(".{}", meshelf_core::MessageId::new());
    let final_path = directory.join(component_with_suffix(root_name, &suffix)?);
    finalize_payload(payload, &final_path, content_kind).await?;
    Ok(final_path)
}

pub(crate) async fn finalize_payload(
    payload: &Path,
    final_path: &Path,
    content_kind: ContentKind,
) -> Result<(), NetError> {
    reject_reparse_point(payload)?;
    let parent = final_path
        .parent()
        .ok_or_else(|| NetError::FileTransfer("destination has no parent".to_owned()))?;
    // This is intentionally repeated immediately before publication.  A checked parent from
    // admission is not enough because another process may replace it before the rename.
    meshelf_platform::require_directory(parent)?;
    if content_kind == ContentKind::File {
        std::fs::hard_link(payload, final_path)?;
        // The no-replace hard link is the publication. Staging cleanup cannot invalidate it.
        tokio::fs::remove_file(payload).await?;
    } else {
        rename_exclusive_portable(payload, final_path)?;
    }
    Ok(())
}

pub(crate) fn collision_candidate(
    directory: &Path,
    root_name: &str,
    content_kind: ContentKind,
    index: usize,
) -> Result<PathBuf, NetError> {
    if index == 1 {
        validate_component(root_name).map_err(generated_component_error)?;
        return Ok(directory.join(root_name));
    }

    let suffix = format!(" ({index})");
    let source = Path::new(root_name);
    let extension = (content_kind == ContentKind::File)
        .then(|| source.extension().and_then(|value| value.to_str()))
        .flatten();
    if let Some(extension) = extension {
        let stem = source
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or(root_name);
        let fixed_bytes = suffix
            .len()
            .checked_add(1)
            .and_then(|value| value.checked_add(extension.len()))
            .ok_or_else(|| {
                NetError::FileTransfer("generated destination name length overflow".to_owned())
            })?;
        if let Some(max_stem_bytes) = MAX_OFFER_PORTABLE_COMPONENT_BYTES.checked_sub(fixed_bytes) {
            let stem = truncate_utf8(stem, max_stem_bytes);
            if !stem.is_empty() {
                let name = format!("{stem}{suffix}.{extension}");
                validate_component(&name).map_err(generated_component_error)?;
                return Ok(directory.join(name));
            }
        }
    }

    Ok(directory.join(component_with_suffix(root_name, &suffix)?))
}

pub(crate) fn component_with_suffix(component: &str, suffix: &str) -> Result<String, NetError> {
    let max_component_bytes = MAX_OFFER_PORTABLE_COMPONENT_BYTES
        .checked_sub(suffix.len())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            NetError::FileTransfer(format!(
                "generated destination suffix is {} bytes; maximum component is {MAX_OFFER_PORTABLE_COMPONENT_BYTES}",
                suffix.len()
            ))
        })?;
    let component = truncate_utf8(component, max_component_bytes);
    if component.is_empty() {
        return Err(NetError::FileTransfer(
            "generated destination suffix leaves no complete UTF-8 character for the name"
                .to_owned(),
        ));
    }
    let name = format!("{component}{suffix}");
    validate_component(&name).map_err(generated_component_error)?;
    Ok(name)
}

fn generated_component_error(error: String) -> NetError {
    NetError::FileTransfer(format!("generated destination name is invalid: {error}"))
}

pub(crate) fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

pub(crate) fn relative_path(value: &str) -> PathBuf {
    meshelf_core::relative_path(value)
}
