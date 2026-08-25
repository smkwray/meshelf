//! Filesystem primitives used by later pull-v2 admission and publication steps.
//!
//! These helpers are deliberately platform-facing and are not called by the production entry
//! point in Step 3. In particular, a free-space report is never a substitute for successful
//! preallocation.

use std::{
    fs::{self, File},
    io::{self, ErrorKind},
    path::Component,
    path::{Path, PathBuf},
};

use fs2::FileExt;

use crate::activation;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FilesystemKey(String);

#[cfg(windows)]
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Inspect one path without following a final link and reject every link-like object that could
/// redirect a destination operation. On Windows the attribute check also catches junctions,
/// which `FileType::is_symlink` does not report.
pub fn reject_reparse_point(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| path_error("inspect destination component", path, error))?;
    reject_reparse_metadata(path, &metadata)?;
    Ok(metadata)
}

fn reject_reparse_metadata(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "destination component is a symbolic link: {}",
                path.display()
            ),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        if metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "destination component is a Windows reparse point: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Walk and create a directory path one component at a time. Existing components are checked
/// with `symlink_metadata`; no unchecked `create_dir_all` traversal is used.
pub fn ensure_directory_tree(path: &Path) -> io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        // A drive prefix and a root are not creatable objects and cannot themselves be reparse
        // points. On Windows `components()` yields `C:` and `\\` separately, so stat-ing the
        // partial path would ask about "the current directory on drive C:" rather than the drive
        // root, which is both meaningless and not what the caller named.
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                reject_reparse_metadata(&current, &metadata)?;
                if !metadata.is_dir() {
                    return Err(io::Error::new(
                        ErrorKind::AlreadyExists,
                        format!(
                            "destination component is not a directory: {}",
                            current.display()
                        ),
                    ));
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|error| path_error("create destination directory", &current, error))?;
                let metadata = reject_reparse_point(&current)?;
                if !metadata.is_dir() {
                    return Err(io::Error::other(format!(
                        "created destination is not a directory: {}",
                        current.display()
                    )));
                }
            }
            Err(error) => return Err(path_error("inspect destination component", &current, error)),
        }
    }
    Ok(())
}

/// Require an existing, non-reparse directory.
pub fn require_directory(path: &Path) -> io::Result<()> {
    let metadata = reject_reparse_point(path)?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("expected directory: {}", path.display()),
        ))
    }
}

/// Create one new regular file and reject a redirected result before it is used.
pub fn create_new_file(path: &Path) -> io::Result<File> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| path_error("create staging file", path, error))?;
    if let Err(error) = reject_reparse_point(path) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

/// Remove an owned staging root without following a final symlink or reparse point.
pub fn remove_owned_tree(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(path_error("inspect owned cleanup root", path, error)),
    };
    reject_reparse_metadata(path, &metadata)?;
    if metadata.is_dir() {
        remove_owned_directory(path)
    } else {
        Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("owned cleanup root is not a directory: {}", path.display()),
        ))
    }
}

fn remove_owned_directory(path: &Path) -> io::Result<()> {
    for entry in
        fs::read_dir(path).map_err(|error| path_error("read owned staging root", path, error))?
    {
        let entry = entry.map_err(|error| path_error("read owned staging entry", path, error))?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)
            .map_err(|error| path_error("inspect owned staging entry", &child, error))?;
        reject_reparse_metadata(&child, &metadata)?;
        if metadata.is_dir() {
            remove_owned_directory(&child)?;
        } else {
            fs::remove_file(&child)
                .map_err(|error| path_error("remove owned staging file", &child, error))?;
        }
    }
    fs::remove_dir(path).map_err(|error| path_error("remove owned staging root", path, error))
}

/// Return an identity suitable for grouping paths that share one filesystem.
pub fn filesystem_key(path: &Path) -> io::Result<FilesystemKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = reject_reparse_point(path)?;
        Ok(FilesystemKey(format!("unix-device:{}", metadata.dev())))
    }

    #[cfg(windows)]
    {
        windows_filesystem_key(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "filesystem identity is unsupported on this platform",
        ))
    }
}

/// Bytes committing to a source object's identity and change state, for detecting that a file
/// changed between being offered and being fetched.
///
/// Unix contributes the device/inode pair, which detects replacement even when every other
/// attribute is identical. Windows deliberately does not: `volume_serial_number` and `file_index`
/// are behind the unstable `windows_by_handle` feature and cannot be used on a stable toolchain, so
/// Windows commits to attributes, creation time, last write time and size instead. That is weaker —
/// a replacement preserving all four would go undetected there — and it is why transferred bytes are
/// still hashed end to end rather than trusting this commitment alone.
///
/// This lives here because `meshelf-net` and `meshelf-control` must stay portable under product
/// invariant 14, and because two copies of a commitment that both sides must compute identically
/// would break revalidation the moment they drifted.
pub fn source_identity_bytes(metadata: &std::fs::Metadata) -> Vec<u8> {
    let mut bytes = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        bytes.extend_from_slice(b"unix");
        bytes.extend_from_slice(&metadata.dev().to_le_bytes());
        bytes.extend_from_slice(&metadata.ino().to_le_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        bytes.extend_from_slice(b"windows");
        bytes.extend_from_slice(&metadata.file_attributes().to_le_bytes());
        bytes.extend_from_slice(&metadata.creation_time().to_le_bytes());
        bytes.extend_from_slice(&metadata.last_write_time().to_le_bytes());
        bytes.extend_from_slice(&metadata.file_size().to_le_bytes());
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        bytes.extend_from_slice(b"portable");
    }
    bytes
}

/// Return bytes available to the current user on the filesystem containing `path`.
pub fn available_space(path: &Path) -> io::Result<u64> {
    fs2::available_space(path).map_err(|error| path_error("read available space for", path, error))
}

/// Return total bytes on the filesystem containing `path`.
pub fn total_space(path: &Path) -> io::Result<u64> {
    fs2::total_space(path).map_err(|error| path_error("read total space for", path, error))
}

/// Preallocate a regular file to at least `length` bytes.
pub fn preallocate(file: &File, length: u64) -> io::Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect file for preallocation", error))?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "preallocation requires a regular file",
        ));
    }
    reject_reparse_metadata(Path::new("<open file>"), &metadata)?;

    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        windows
    ))]
    {
        file.allocate(length)
            .map_err(|error| io_error("preallocate regular file", error))?;
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        windows
    )))]
    {
        let _ = (file, length);
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "regular-file preallocation is unsupported on this platform",
        ));
    }

    let resulting_length = file
        .metadata()
        .map_err(|error| io_error("verify preallocated file length", error))?
        .len();
    if resulting_length < length {
        return Err(io::Error::other(format!(
            "preallocation returned a file of {resulting_length} bytes, below the declared {length} bytes"
        )));
    }
    Ok(())
}

/// Apply owner-only permissions where the platform supports the existing activation approach.
pub fn apply_owner_only_permissions(path: &Path) -> io::Result<()> {
    reject_reparse_point(path)?;
    activation::make_owner_only(path)
}

/// Flush directory metadata so a preceding rename is durable where the platform supports it.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    let metadata = reject_reparse_point(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("directory sync requires a directory: {}", path.display()),
        ));
    }

    #[cfg(unix)]
    {
        File::open(path)
            .map_err(|error| path_error("open directory for sync", path, error))?
            .sync_all()
            .map_err(|error| path_error("sync directory", path, error))
    }

    #[cfg(windows)]
    {
        windows_sync_directory(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "directory synchronization is unsupported on this platform",
        ))
    }
}

fn path_error(action: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{action} {}: {error}", path.display()),
    )
}

fn io_error(action: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{action}: {error}"))
}

/// Atomically rename a staged directory without replacing an existing destination.
pub fn rename_exclusive_portable(payload: &Path, final_path: &Path) -> io::Result<()> {
    reject_reparse_point(payload)?;
    if let Some(parent) = final_path.parent() {
        require_directory(parent)?;
    }
    #[cfg(not(windows))]
    {
        renamore::rename_exclusive(payload, final_path)
    }
    #[cfg(windows)]
    {
        let payload = windows_verbatim_path(payload)?;
        let final_path = windows_verbatim_path(final_path)?;
        renamore::rename_exclusive(&payload, &final_path)
    }
}

/// Convert an absolute path to the Windows verbatim spelling used for long and exact filesystem
/// operations. This function is only compiled on Windows.
#[cfg(windows)]
pub fn windows_verbatim_path(path: &Path) -> io::Result<PathBuf> {
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
    };

    const SEP: u16 = b'\\' as u16;
    const DOT: u16 = b'.' as u16;
    const QUERY: u16 = b'?' as u16;
    const U: u16 = b'U' as u16;
    const N: u16 = b'N' as u16;
    const C: u16 = b'C' as u16;
    const VERBATIM_PREFIX: &[u16] = &[SEP, SEP, QUERY, SEP];
    const NT_PREFIX: &[u16] = &[SEP, QUERY, QUERY, SEP];
    const DEVICE_PREFIX: &[u16] = &[SEP, SEP, DOT, SEP];
    const UNC_PREFIX: &[u16] = &[SEP, SEP, QUERY, SEP, U, N, C, SEP];

    let absolute = std::path::absolute(path)?;
    let wide = absolute.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.starts_with(VERBATIM_PREFIX) || wide.starts_with(NT_PREFIX) {
        return Ok(absolute);
    }

    let (prefix, body) = if wide.starts_with(DEVICE_PREFIX) {
        (VERBATIM_PREFIX, &wide[DEVICE_PREFIX.len()..])
    } else if wide.starts_with(&[SEP, SEP]) {
        (UNC_PREFIX, &wide[2..])
    } else {
        (VERBATIM_PREFIX, wide.as_slice())
    };
    let mut verbatim = Vec::with_capacity(prefix.len() + body.len());
    verbatim.extend_from_slice(prefix);
    verbatim.extend_from_slice(body);
    Ok(PathBuf::from(OsString::from_wide(&verbatim)))
}

#[cfg(windows)]
fn windows_filesystem_key(path: &Path) -> io::Result<FilesystemKey> {
    use std::{os::windows::ffi::OsStrExt, ptr};

    let path_utf16: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut volume_path = vec![0_u16; 32_768];
    let volume_path_length = unsafe {
        GetVolumePathNameW(
            path_utf16.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    };
    if volume_path_length == 0 {
        return Err(path_error(
            "identify filesystem volume for",
            path,
            io::Error::last_os_error(),
        ));
    }

    let mut serial = 0_u32;
    let ok = unsafe {
        GetVolumeInformationW(
            volume_path.as_ptr(),
            ptr::null_mut(),
            0,
            &mut serial,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return Err(path_error(
            "read filesystem identity for",
            path,
            io::Error::last_os_error(),
        ));
    }
    Ok(FilesystemKey(format!("windows-volume:{serial:08x}")))
}

#[cfg(windows)]
fn windows_sync_directory(path: &Path) -> io::Result<()> {
    use std::{
        ffi::{OsStr, c_void},
        os::windows::ffi::OsStrExt,
        ptr,
    };

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const INVALID_HANDLE_VALUE: *mut c_void = -1_isize as *mut c_void;
    const OPEN_EXISTING: u32 = 3;

    let path_utf16: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            path_utf16.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(path_error(
            "open directory for sync",
            path,
            io::Error::last_os_error(),
        ));
    }

    let flush_result = unsafe { FlushFileBuffers(handle) };
    let flush_error = if flush_result == 0 {
        Some(path_error(
            "sync directory",
            path,
            io::Error::last_os_error(),
        ))
    } else {
        None
    };
    let close_result = unsafe { CloseHandle(handle) };
    if let Some(error) = flush_error {
        return Err(error);
    }
    if close_result == 0 {
        return Err(path_error(
            "close directory after sync",
            path,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *mut std::ffi::c_void,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn FlushFileBuffers(handle: *mut std::ffi::c_void) -> i32;
    fn GetVolumeInformationW(
        root_path_name: *const u16,
        volume_name_buffer: *mut u16,
        volume_name_size: u32,
        volume_serial_number: *mut u32,
        maximum_component_length: *mut u32,
        file_system_flags: *mut u32,
        file_system_name_buffer: *mut u16,
        file_system_name_size: u32,
    ) -> i32;
    fn GetVolumePathNameW(
        file_name: *const u16,
        volume_path_name: *mut u16,
        buffer_length: u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        path::{Path, PathBuf},
    };

    use meshelf_core::MessageId;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("meshelf-filesystem-test-{}", MessageId::new()));
            fs::create_dir(&path).expect("create unique temporary directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn filesystem_key_groups_two_paths_on_same_volume() {
        let directory = TestDirectory::new();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        fs::create_dir(&first).expect("create first directory");
        fs::create_dir(&second).expect("create second directory");

        assert_eq!(
            filesystem_key(&first).expect("first filesystem key"),
            filesystem_key(&second).expect("second filesystem key")
        );
    }

    #[test]
    fn filesystem_key_is_available_for_a_freshly_created_directory() {
        let directory = TestDirectory::new();
        assert!(filesystem_key(directory.path()).is_ok());
    }

    #[test]
    fn available_space_is_reported_and_is_not_zero_for_temp() {
        let directory = TestDirectory::new();
        let available = available_space(directory.path()).expect("available temporary space");
        assert!(
            available > 0,
            "temporary filesystem reported zero available bytes"
        );
    }

    #[test]
    fn preallocation_extends_the_file_to_the_declared_length() {
        let directory = TestDirectory::new();
        let path = directory.path().join("payload");
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("create payload");

        preallocate(&file, 4096).expect("preallocate payload");
        assert!(file.metadata().expect("payload metadata").len() >= 4096);
    }

    #[test]
    fn preallocation_failure_is_an_explicit_error_not_a_silent_success() {
        let directory = TestDirectory::new();
        let path = directory.path().join("read-only");
        File::create(&path).expect("create read-only test file");
        let file = File::open(&path).expect("open read-only test file");

        let result = preallocate(&file, 4096);
        assert!(
            result.is_err(),
            "read-only preallocation must fail explicitly"
        );
    }

    #[test]
    fn owner_only_permissions_are_applied_where_the_platform_supports_them() {
        let directory = TestDirectory::new();
        let path = directory.path().join("staging");
        fs::create_dir(&path).expect("create staging directory");

        apply_owner_only_permissions(&path).expect("apply owner-only permissions");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&path)
                .expect("staging metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "group/other permissions remain enabled: {mode:o}"
            );
            assert_eq!(
                mode & 0o700,
                0o700,
                "owner directory permissions are missing: {mode:o}"
            );
        }
    }

    #[test]
    fn directory_sync_succeeds_for_a_real_directory() {
        let directory = TestDirectory::new();
        let child = directory.path().join("child");
        fs::create_dir(&child).expect("create child directory");
        sync_directory(directory.path()).expect("sync real directory");
    }

    #[cfg(unix)]
    #[test]
    fn unix_symlink_ancestor_is_rejected_without_payload() {
        let directory = TestDirectory::new();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::create_dir(&target).expect("create target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink ancestor");

        let destination = link.join("destination");
        assert!(ensure_directory_tree(&destination).is_err());
        assert!(!destination.join("payload").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_junction_destination_is_rejected_without_payload() {
        let directory = TestDirectory::new();
        let target = directory.path().join("target");
        let junction = directory.path().join("junction");
        fs::create_dir(&target).expect("create target");
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(&target)
            .status()
            .expect("run mklink junction");
        assert!(status.success(), "mklink /J failed: {status}");

        let destination = junction.join("destination");
        assert!(ensure_directory_tree(&destination).is_err());
        assert!(!destination.join("payload").exists());
    }
}
