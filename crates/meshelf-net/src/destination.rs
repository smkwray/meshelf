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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn collision_candidates_stay_within_portable_component_limit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let folder_root = "a".repeat(MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        let folder_candidate =
            collision_candidate(directory.path(), &folder_root, ContentKind::Folder, 2)
                .expect("folder collision candidate");
        let folder_name = folder_candidate
            .file_name()
            .and_then(|value| value.to_str())
            .expect("folder collision name");
        assert_eq!(folder_name.len(), MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        assert!(folder_name.ends_with(" (2)"));
        validate_component(folder_name).expect("portable folder collision name");

        let file_root = format!("{}.txt", "b".repeat(MAX_OFFER_PORTABLE_COMPONENT_BYTES - 4));
        let file_candidate =
            collision_candidate(directory.path(), &file_root, ContentKind::File, 9999)
                .expect("file collision candidate");
        let file_name = file_candidate
            .file_name()
            .and_then(|value| value.to_str())
            .expect("file collision name");
        assert_eq!(file_name.len(), MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        assert!(file_name.ends_with(" (9999).txt"));
        validate_component(file_name).expect("portable file collision name");

        let unicode_root = format!("{}a", "é".repeat(127));
        let unicode_candidate =
            collision_candidate(directory.path(), &unicode_root, ContentKind::Folder, 2)
                .expect("UTF-8 collision candidate");
        let unicode_name = unicode_candidate
            .file_name()
            .and_then(|value| value.to_str())
            .expect("UTF-8 collision name");
        assert!(unicode_name.len() <= MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        assert!(unicode_name.ends_with(" (2)"));
        validate_component(unicode_name).expect("portable UTF-8 collision name");

        let fallback_suffix = format!(".{}", meshelf_core::MessageId::new());
        let fallback_name = component_with_suffix(&folder_root, &fallback_suffix)
            .expect("portable UUID fallback name");
        assert!(fallback_name.len() <= MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        validate_component(&fallback_name).expect("portable UUID fallback name");
    }

    #[test]
    fn generated_collision_names_reject_degenerate_suffix_budgets() {
        let at_ceiling = "x".repeat(MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        let over_ceiling = "x".repeat(MAX_OFFER_PORTABLE_COMPONENT_BYTES + 1);
        assert!(component_with_suffix("stem", &at_ceiling).is_err());
        assert!(component_with_suffix("stem", &over_ceiling).is_err());

        let almost_ceiling = "x".repeat(MAX_OFFER_PORTABLE_COMPONENT_BYTES - 1);
        assert!(component_with_suffix("é", &almost_ceiling).is_err());
        assert_eq!(truncate_utf8("é", 1), "");

        let directory = tempfile::tempdir().expect("temporary directory");
        let dotfile = collision_candidate(directory.path(), ".bashrc", ContentKind::File, 2)
            .expect("dotfile collision candidate");
        assert_eq!(dotfile, directory.path().join(".bashrc (2)"));

        let long_extension = format!("a.{}", "x".repeat(250));
        let long_extension_candidate =
            collision_candidate(directory.path(), &long_extension, ContentKind::File, 2)
                .expect("long-extension collision candidate");
        let long_extension_name = long_extension_candidate
            .file_name()
            .and_then(|value| value.to_str())
            .expect("long-extension collision name");
        assert!(long_extension_name.len() <= MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        assert!(long_extension_name.ends_with(" (2)"));
        validate_component(long_extension_name).expect("portable long-extension collision name");
    }

    #[tokio::test]
    async fn max_length_folder_collision_finalizes_on_the_real_filesystem() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let incoming = directory.path().join("incoming");
        std::fs::create_dir(&incoming).expect("incoming directory");
        let root_name = "a".repeat(MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        let existing = incoming.join(&root_name);
        std::fs::create_dir(&existing).expect("existing maximum-length destination");

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            assert!(existing.as_os_str().encode_wide().count() >= 260);
        }

        let payload = directory.path().join("payload");
        std::fs::create_dir(&payload).expect("payload directory");
        std::fs::write(payload.join("item.txt"), b"payload").expect("payload file");

        let final_path = finalize_payload_without_overwrite(
            &payload,
            &incoming,
            &root_name,
            ContentKind::Folder,
        )
        .await
        .expect("maximum-length exclusive folder finalization");
        let final_name = final_path
            .file_name()
            .and_then(|value| value.to_str())
            .expect("maximum-length final name");

        assert_eq!(final_name.len(), MAX_OFFER_PORTABLE_COMPONENT_BYTES);
        assert!(final_name.ends_with(" (2)"));
        validate_component(final_name).expect("portable maximum-length final name");
        assert!(existing.is_dir());
        assert_eq!(
            std::fs::read(final_path.join("item.txt")).expect("published payload"),
            b"payload"
        );
    }

    #[tokio::test]
    async fn folder_finalization_uses_atomic_no_replace_and_next_collision_name() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let incoming = directory.path().join("incoming");
        std::fs::create_dir(&incoming).expect("incoming directory");
        let existing = incoming.join("bundle");
        std::fs::create_dir(&existing).expect("existing empty destination");
        let payload = directory.path().join("payload");
        std::fs::create_dir(&payload).expect("payload directory");
        std::fs::write(payload.join("item.txt"), b"payload").expect("payload file");

        let final_path =
            finalize_payload_without_overwrite(&payload, &incoming, "bundle", ContentKind::Folder)
                .await
                .expect("exclusive folder finalization");

        assert_eq!(final_path, incoming.join("bundle (2)"));
        assert!(existing.is_dir());
        assert!(
            std::fs::read_dir(&existing)
                .expect("read original destination")
                .next()
                .is_none()
        );
        assert_eq!(
            std::fs::read(final_path.join("item.txt")).expect("published payload"),
            b"payload"
        );
    }

    #[test]
    fn concurrent_folder_finalization_never_overwrites() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let incoming = directory.path().join("incoming");
        std::fs::create_dir(&incoming).expect("incoming directory");
        let first_payload = directory.path().join("first-payload");
        let second_payload = directory.path().join("second-payload");
        std::fs::create_dir(&first_payload).expect("first payload directory");
        std::fs::create_dir(&second_payload).expect("second payload directory");
        std::fs::write(first_payload.join("first.txt"), b"first").expect("first payload");
        std::fs::write(second_payload.join("second.txt"), b"second").expect("second payload");

        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for payload in [first_payload, second_payload] {
            let incoming = incoming.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("test runtime");
                barrier.wait();
                runtime.block_on(finalize_payload_without_overwrite(
                    &payload,
                    &incoming,
                    "bundle",
                    ContentKind::Folder,
                ))
            }));
        }

        barrier.wait();
        let mut final_paths = workers
            .into_iter()
            .map(|worker| {
                worker
                    .join()
                    .expect("finalization worker")
                    .expect("exclusive finalization")
            })
            .collect::<Vec<_>>();
        final_paths.sort();

        assert_eq!(
            final_paths,
            vec![incoming.join("bundle"), incoming.join("bundle (2)")]
        );
        let published_names = final_paths
            .iter()
            .flat_map(|path| {
                std::fs::read_dir(path)
                    .expect("published directory")
                    .map(|entry| {
                        entry
                            .expect("published entry")
                            .file_name()
                            .to_string_lossy()
                            .into_owned()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            published_names,
            std::collections::BTreeSet::from(["first.txt".to_owned(), "second.txt".to_owned()])
        );
    }
}
