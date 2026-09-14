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
    if content_kind == ContentKind::File {
        link_file_without_replace(payload, final_path)?;
        // The no-replace hard link is the publication. Staging cleanup cannot invalidate it.
        tokio::fs::remove_file(payload).await?;
    } else {
        recheck_publication_source_and_parent(payload, final_path)?;
        rename_exclusive_portable(payload, final_path)?;
    }
    Ok(())
}

/// The file publication kernel: a hard link fails with `AlreadyExists` when anything occupies
/// `final_path`, so it can never replace an existing object. Success is the publication.
///
/// Android app sandboxes commonly deny hard links (SELinux `EPERM`) even inside the same
/// private directory. Fall back to an exclusive create + copy, which preserves no-replace.
fn link_file_without_replace(payload: &Path, final_path: &Path) -> Result<(), NetError> {
    recheck_publication_source_and_parent(payload, final_path)?;
    match std::fs::hard_link(payload, final_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(NetError::Io(error)),
        Err(error) if hard_link_unavailable(&error) => {
            copy_file_without_replace(payload, final_path)
        }
        Err(error) => Err(NetError::Io(error)),
    }
}

fn hard_link_unavailable(error: &std::io::Error) -> bool {
    // Android sandboxes often return EPERM for hard_link; some hosts use ENOSYS/EOPNOTSUPP.
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
    ) || matches!(error.raw_os_error(), Some(1 | 38 | 95))
}

fn copy_file_without_replace(payload: &Path, final_path: &Path) -> Result<(), NetError> {
    let mut source = std::fs::File::open(payload).map_err(NetError::Io)?;
    let mut destination = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(final_path)
    {
        Ok(file) => file,
        Err(error) => return Err(NetError::Io(error)),
    };
    if let Err(error) = std::io::copy(&mut source, &mut destination) {
        let _ = std::fs::remove_file(final_path);
        return Err(NetError::Io(error));
    }
    if let Err(error) = destination.sync_all() {
        let _ = std::fs::remove_file(final_path);
        return Err(NetError::Io(error));
    }
    Ok(())
}

fn recheck_publication_source_and_parent(
    payload: &Path,
    final_path: &Path,
) -> Result<(), NetError> {
    reject_reparse_point(payload)?;
    let parent = final_path
        .parent()
        .ok_or_else(|| NetError::FileTransfer("destination has no parent".to_owned()))?;
    // This is intentionally repeated immediately before publication.  A checked parent from
    // admission is not enough because another process may replace it before the rename.
    meshelf_platform::require_directory(parent)?;
    Ok(())
}

/// Why an exact `--output` path was refused before any capture request was sent.
///
/// An agent that names a path must receive exactly that file or nothing, so every condition
/// under which publication could land elsewhere, replace something, or create directories the
/// agent did not ask for is a refusal rather than an adjustment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExactOutputRefusal {
    /// The caller must absolutize the path; a relative path depends on a working directory.
    #[error("output path is not absolute")]
    NotAbsolute,
    /// The final component is empty, `.`, `..`, a trailing separator, or not portable.
    #[error("output file name is invalid")]
    InvalidName,
    /// The parent does not exist; exact output never creates directories.
    #[error("output parent directory does not exist")]
    ParentMissing,
    /// The parent exists but is not a directory.
    #[error("output parent is not a directory")]
    ParentNotDirectory,
    /// The immediate parent is a symbolic link or reparse point that could redirect publication.
    #[error("output parent is a symbolic link or reparse point")]
    ParentIsLink,
    /// The target is a real directory.
    #[error("output path is a directory")]
    IsDirectory,
    /// Something that is not a real directory occupies the target, including any link.
    #[error("output path already exists")]
    Exists,
    /// The parent or target could not be inspected, so absence cannot be established.
    #[error("output path could not be inspected: {0:?}")]
    InspectFailed(std::io::ErrorKind),
}

impl ExactOutputRefusal {
    /// Stable machine-readable code reported to the requesting agent.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotAbsolute => "output_not_absolute",
            Self::InvalidName => "output_name_invalid",
            Self::ParentMissing => "output_parent_missing",
            Self::ParentNotDirectory => "output_parent_not_directory",
            Self::ParentIsLink => "output_parent_is_link",
            Self::IsDirectory => "output_is_directory",
            Self::Exists => "output_exists",
            Self::InspectFailed(_) => "output_inspect_failed",
        }
    }
}

/// Why an exact output file was not (or not provably) published.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExactPublishError {
    /// Another object appeared at the target after preflight. Nothing was published, the existing
    /// object is untouched, and the staging file is left in place for the caller to remove.
    #[error("output_exists: the exact output path was created by another process")]
    OutputExists,
    /// Publication did not happen (for example the parent stopped being a real directory). The
    /// staging file, if it still exists, is the caller's to remove.
    #[error("exact output was not published: {0}")]
    NotPublished(NetError),
    /// The target now holds the staged bytes, but removing the staging name or syncing the parent
    /// failed, so durability is unproven. Never retry and never remove the target on this basis.
    #[error("exact output was published but not confirmed durable: {0}")]
    AfterPublication(std::io::Error),
}

/// Refuse an exact output path unless publication could land at exactly `path` with nothing
/// replaced and no directory created. The resident runs it before a capture request is sent,
/// and the receiver runs it again at admission, because the path may change in between.
pub fn preflight_exact_output(path: &Path) -> Result<PathBuf, ExactOutputRefusal> {
    if !path.is_absolute() {
        return Err(ExactOutputRefusal::NotAbsolute);
    }
    let name = literal_file_name(path).ok_or(ExactOutputRefusal::InvalidName)?;
    validate_component(name).map_err(|_| ExactOutputRefusal::InvalidName)?;
    let parent = path.parent().ok_or(ExactOutputRefusal::InvalidName)?;

    let parent_metadata = match reject_reparse_point(parent) {
        Ok(metadata) => metadata,
        Err(error) => return Err(classify_parent_error(parent, &error)),
    };
    if !parent_metadata.is_dir() {
        return Err(ExactOutputRefusal::ParentNotDirectory);
    }

    // Never follow a link at the target: a link of any kind, even a broken one, is an object.
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && reject_reparse_point(path).is_ok() => {
            Err(ExactOutputRefusal::IsDirectory)
        }
        Ok(_) => Err(ExactOutputRefusal::Exists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(error) => Err(ExactOutputRefusal::InspectFailed(error.kind())),
    }
}

fn classify_parent_error(parent: &Path, error: &std::io::Error) -> ExactOutputRefusal {
    match error.kind() {
        // A non-directory ancestor means the parent cannot exist either.
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
            ExactOutputRefusal::ParentMissing
        }
        // `reject_reparse_point` reports a link as PermissionDenied; a real permission failure
        // leaves the parent uninspectable, so tell them apart by whether it can be inspected.
        std::io::ErrorKind::PermissionDenied if std::fs::symlink_metadata(parent).is_ok() => {
            ExactOutputRefusal::ParentIsLink
        }
        kind => ExactOutputRefusal::InspectFailed(kind),
    }
}

/// The final component, only when it is spelled literally at the end of `path`.
///
/// `Path::file_name` normalizes `dir/` and `dir/.` to `dir`, which would publish a file where the
/// agent named a directory. Exact output requires the raw path to end in a separator followed by
/// exactly that name; a non-UTF-8 name is refused because it cannot be validated as portable.
fn literal_file_name(path: &Path) -> Option<&str> {
    let name = path.file_name()?;
    let prefix = path
        .as_os_str()
        .as_encoded_bytes()
        .strip_suffix(name.as_encoded_bytes())?;
    let follows_separator = prefix
        .last()
        .is_some_and(|byte| byte.is_ascii() && std::path::is_separator(char::from(*byte)));
    follows_separator.then_some(()).and(name.to_str())
}

/// Publish a staged file at exactly `final_path` or not at all, then make it durable.
///
/// The staged file lives in a staging directory inside the exact output's own parent, so the
/// publishing link never crosses filesystems. On `OutputExists` or `NotPublished` the staging
/// file is deliberately left for the caller, which already owns cleanup for every other
/// pre-publication failure.
pub(crate) fn publish_exact_file(
    staging: &Path,
    final_path: &Path,
) -> Result<(), ExactPublishError> {
    match link_file_without_replace(staging, final_path) {
        Ok(()) => {}
        Err(NetError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ExactPublishError::OutputExists);
        }
        Err(error) => return Err(ExactPublishError::NotPublished(error)),
    }
    let removed = std::fs::remove_file(staging);
    // Sync even when removal failed: the link itself is the publication that must be durable.
    let synced = final_path
        .parent()
        .map_or(Ok(()), meshelf_platform::sync_directory);
    removed
        .and(synced)
        .map_err(ExactPublishError::AfterPublication)
}

/// True when an I/O failure means the destination filesystem is out of space or quota.
///
/// Classified by kind rather than raw code so errors re-wrapped by `meshelf-platform` (which
/// preserve the kind but drop the OS code) still classify. The standard library maps ENOSPC to
/// `StorageFull` and EDQUOT to `QuotaExceeded` on Unix, whose numeric values differ between
/// macOS and Linux, and Windows `ERROR_DISK_FULL` (112) and `ERROR_HANDLE_DISK_FULL` (39) to
/// `StorageFull`.
pub(crate) fn is_insufficient_space(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
    )
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
    fn exclusive_copy_publishes_without_replacing_existing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let payload = directory.path().join("payload.bin");
        let final_path = directory.path().join("out.bin");
        std::fs::write(&payload, b"verified-bytes").expect("payload");
        std::fs::write(&final_path, b"keep-me").expect("existing");

        let error = copy_file_without_replace(&payload, &final_path).expect_err("must not replace");
        assert!(matches!(error, NetError::Io(_)));
        assert_eq!(
            std::fs::read(&final_path).expect("existing bytes"),
            b"keep-me"
        );

        let published = directory.path().join("published.bin");
        copy_file_without_replace(&payload, &published).expect("exclusive copy");
        assert_eq!(
            std::fs::read(&published).expect("published bytes"),
            b"verified-bytes"
        );
    }

    #[tokio::test]
    async fn file_finalize_publishes_and_removes_staging_payload() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let payload = directory.path().join("payload.bin");
        let final_path = directory.path().join("candidate.bin");
        std::fs::write(&payload, b"g07-file").expect("payload");
        finalize_payload(&payload, &final_path, ContentKind::File)
            .await
            .expect("finalize");
        assert_eq!(std::fs::read(&final_path).expect("published"), b"g07-file");
        assert!(!payload.exists());
    }

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

    /// The capture receiver's staging layout: one payload file inside a hidden staging directory
    /// in the exact output's own parent.
    fn staged(final_path: &Path, bytes: &[u8]) -> PathBuf {
        use std::io::Write;

        let staging_root = final_path.parent().expect("output parent").join(format!(
            ".meshelf-capture-{}",
            meshelf_core::ActivationId::new()
        ));
        std::fs::create_dir(&staging_root).expect("staging directory");
        let staging = staging_root.join("payload");
        let mut file = meshelf_platform::create_new_file(&staging).expect("staging file");
        file.write_all(bytes).expect("write staged bytes");
        file.sync_all().expect("sync staged bytes");
        staging
    }

    fn entry_names(directory: &Path) -> std::collections::BTreeSet<String> {
        std::fs::read_dir(directory)
            .expect("read directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn exact_output_refusal_codes_are_the_stable_strings_agents_match_on() {
        // The design consult names these three codes as the agent-facing contract.
        assert_eq!(ExactOutputRefusal::Exists.code(), "output_exists");
        assert_eq!(
            ExactOutputRefusal::IsDirectory.code(),
            "output_is_directory"
        );
        assert_eq!(
            ExactOutputRefusal::ParentMissing.code(),
            "output_parent_missing"
        );
    }

    #[test]
    fn preflight_refuses_an_existing_file_so_an_agent_never_overwrites_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("router-label.jpg");
        std::fs::write(&target, b"keep me").expect("existing file");

        assert_eq!(
            preflight_exact_output(&target),
            Err(ExactOutputRefusal::Exists)
        );
        assert_eq!(std::fs::read(&target).expect("existing file"), b"keep me");
    }

    #[test]
    fn preflight_refuses_a_directory_target_instead_of_writing_inside_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("photos");
        std::fs::create_dir(&target).expect("existing directory");

        assert_eq!(
            preflight_exact_output(&target),
            Err(ExactOutputRefusal::IsDirectory)
        );
        assert!(entry_names(&target).is_empty());
    }

    #[test]
    fn preflight_refuses_a_missing_parent_without_creating_any_directory() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("missing");
        let target = missing.join("nested").join("router-label.jpg");

        assert_eq!(
            preflight_exact_output(&target),
            Err(ExactOutputRefusal::ParentMissing)
        );
        assert!(std::fs::symlink_metadata(&missing).is_err());
        assert!(entry_names(directory.path()).is_empty());
    }

    #[test]
    fn preflight_refuses_a_parent_that_is_a_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let file = directory.path().join("not-a-directory");
        std::fs::write(&file, b"file").expect("parent file");

        assert_eq!(
            preflight_exact_output(&file.join("router-label.jpg")),
            Err(ExactOutputRefusal::ParentNotDirectory)
        );
    }

    #[test]
    fn preflight_refuses_a_relative_path_whose_meaning_depends_on_the_working_directory() {
        assert_eq!(
            preflight_exact_output(Path::new("router-label.jpg")),
            Err(ExactOutputRefusal::NotAbsolute)
        );
        assert_eq!(
            preflight_exact_output(Path::new("photos/router-label.jpg")),
            Err(ExactOutputRefusal::NotAbsolute)
        );
    }

    #[test]
    fn preflight_refuses_a_final_component_that_does_not_literally_name_a_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().as_os_str().to_owned();
        let separator = std::path::MAIN_SEPARATOR;
        // `Path::file_name` would normalize the trailing-separator and trailing-`.` spellings to
        // an existing name, publishing somewhere other than what the agent wrote.
        for suffix in [
            format!("{separator}.."),
            format!("{separator}."),
            format!("{separator}photo{separator}"),
            format!("{separator}photo{separator}."),
            format!("{separator}a:b.jpg"),
            format!("{separator}CON"),
        ] {
            let mut spelled = root.clone();
            spelled.push(&suffix);
            assert_eq!(
                preflight_exact_output(Path::new(&spelled)),
                Err(ExactOutputRefusal::InvalidName),
                "{suffix:?}"
            );
        }
        assert!(entry_names(directory.path()).is_empty());
        assert_eq!(
            preflight_exact_output(&directory.path().join("router-label.jpg")),
            Ok(directory.path().join("router-label.jpg"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn preflight_treats_a_symlink_target_as_existing_and_never_follows_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let victim = directory.path().join("victim.txt");
        std::fs::write(&victim, b"victim").expect("link target");
        let file_link = directory.path().join("router-label.jpg");
        std::os::unix::fs::symlink(&victim, &file_link).expect("file symlink");
        let victim_directory = directory.path().join("victim-directory");
        std::fs::create_dir(&victim_directory).expect("directory link target");
        let directory_link = directory.path().join("photos");
        std::os::unix::fs::symlink(&victim_directory, &directory_link).expect("directory symlink");

        assert_eq!(
            preflight_exact_output(&file_link),
            Err(ExactOutputRefusal::Exists)
        );
        // A link to a directory is still a link, not a real directory.
        assert_eq!(
            preflight_exact_output(&directory_link),
            Err(ExactOutputRefusal::Exists)
        );
        assert_eq!(std::fs::read(&victim).expect("link target"), b"victim");
        assert!(entry_names(&victim_directory).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn preflight_treats_a_broken_symlink_target_as_existing() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let dangling = directory.path().join("absent");
        let link = directory.path().join("router-label.jpg");
        std::os::unix::fs::symlink(&dangling, &link).expect("broken symlink");

        assert_eq!(
            preflight_exact_output(&link),
            Err(ExactOutputRefusal::Exists)
        );
        assert!(std::fs::symlink_metadata(&dangling).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn preflight_refuses_a_symlinked_parent_that_could_redirect_publication() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let elsewhere = directory.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("link target directory");
        let parent = directory.path().join("photos");
        std::os::unix::fs::symlink(&elsewhere, &parent).expect("parent symlink");

        assert_eq!(
            preflight_exact_output(&parent.join("router-label.jpg")),
            Err(ExactOutputRefusal::ParentIsLink)
        );
        assert!(entry_names(&elsewhere).is_empty());
    }

    #[test]
    fn exact_publication_lands_at_exactly_the_named_path_and_nowhere_else() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target =
            preflight_exact_output(&directory.path().join("router-label.jpg")).expect("preflight");
        let staging = staged(&target, b"photograph bytes");

        publish_exact_file(&staging, &target).expect("exact publication");

        assert_eq!(
            std::fs::read(&target).expect("published file"),
            b"photograph bytes"
        );
        assert!(std::fs::symlink_metadata(&staging).is_err());
        assert!(std::fs::symlink_metadata(directory.path().join("router-label (2).jpg")).is_err());
        // Publication moved the payload out; the staging directory is empty and the caller's
        // to remove, which `remove_dir` proves by refusing a directory that still holds anything.
        std::fs::remove_dir(staging.parent().expect("staging directory"))
            .expect("staging directory is empty after publication");
        assert_eq!(
            entry_names(directory.path()),
            std::collections::BTreeSet::from(["router-label.jpg".to_owned()])
        );
    }

    #[test]
    fn exact_publication_refuses_a_target_created_after_preflight_and_leaves_it_untouched() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = preflight_exact_output(&directory.path().join("router-label.jpg"))
            .expect("target absent at preflight");
        let staging = staged(&target, b"photograph bytes");
        std::fs::write(&target, b"another process").expect("racing writer");

        assert!(matches!(
            publish_exact_file(&staging, &target),
            Err(ExactPublishError::OutputExists)
        ));
        assert_eq!(
            std::fs::read(&target).expect("racing file"),
            b"another process"
        );
        // Documented contract: on collision the staging file remains for the caller to clean.
        assert_eq!(
            std::fs::read(&staging).expect("staging retained"),
            b"photograph bytes"
        );
        assert!(std::fs::symlink_metadata(directory.path().join("router-label (2).jpg")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn exact_publication_rechecks_a_parent_swapped_for_a_link_after_preflight() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let parent = directory.path().join("photos");
        std::fs::create_dir(&parent).expect("output parent");
        let target = preflight_exact_output(&parent.join("router-label.jpg")).expect("preflight");
        let staging = staged(&target, b"photograph bytes");
        let staging_name = staging.file_name().expect("staging name").to_owned();

        let elsewhere = directory.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("redirect target");
        std::fs::rename(&parent, directory.path().join("photos-old")).expect("move parent");
        std::os::unix::fs::symlink(&elsewhere, &parent).expect("swap parent for link");
        // Make the staging path resolve through the link so only the parent recheck can refuse.
        std::fs::write(elsewhere.join(&staging_name), b"photograph bytes").expect("decoy staging");

        assert!(matches!(
            publish_exact_file(&staging, &target),
            Err(ExactPublishError::NotPublished(_))
        ));
        assert!(std::fs::symlink_metadata(elsewhere.join("router-label.jpg")).is_err());
    }

    #[test]
    fn full_disk_and_quota_errors_classify_as_insufficient_space() {
        #[cfg(unix)]
        let codes: &[i32] = &[
            28, // ENOSPC on macOS and Linux
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            69, // EDQUOT on Apple platforms
            #[cfg(any(target_os = "linux", target_os = "android"))]
            122, // EDQUOT on Linux and Android
        ];
        #[cfg(windows)]
        let codes: &[i32] = &[
            112, // ERROR_DISK_FULL
            39,  // ERROR_HANDLE_DISK_FULL
        ];
        #[cfg(not(any(unix, windows)))]
        let codes: &[i32] = &[];

        for code in codes {
            let error = std::io::Error::from_raw_os_error(*code);
            assert!(is_insufficient_space(&error), "raw OS error {code}");
            // meshelf-platform re-wraps errors with context, keeping the kind but not the code.
            let wrapped =
                std::io::Error::new(error.kind(), format!("create staging file: {error}"));
            assert!(is_insufficient_space(&wrapped), "wrapped OS error {code}");
        }
    }

    #[test]
    fn permission_and_collision_errors_are_not_insufficient_space() {
        #[cfg(unix)]
        let permission_denied = 13; // EACCES
        #[cfg(windows)]
        let permission_denied = 5; // ERROR_ACCESS_DENIED
        #[cfg(any(unix, windows))]
        assert!(!is_insufficient_space(&std::io::Error::from_raw_os_error(
            permission_denied
        )));
        assert!(!is_insufficient_space(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
        assert!(!is_insufficient_space(&std::io::Error::from(
            std::io::ErrorKind::AlreadyExists
        )));
    }
}
