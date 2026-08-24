//! Filesystem primitives used by later pull-v2 admission and publication steps.
//!
//! These helpers are deliberately platform-facing and are not called by the production entry
//! point in Step 3. In particular, a free-space report is never a substitute for successful
//! preallocation.

use std::{
    fs::{self, File},
    io::{self, ErrorKind},
    path::Path,
};

use fs2::FileExt;

use crate::activation;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FilesystemKey(String);

/// Return an identity suitable for grouping paths that share one filesystem.
pub fn filesystem_key(path: &Path) -> io::Result<FilesystemKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata =
            fs::metadata(path).map_err(|error| path_error("identify filesystem", path, error))?;
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
    fs::metadata(path)
        .map_err(|error| path_error("inspect path for owner-only permissions", path, error))?;
    activation::make_owner_only(path)
}

/// Flush directory metadata so a preceding rename is durable where the platform supports it.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    let metadata =
        fs::metadata(path).map_err(|error| path_error("inspect directory", path, error))?;
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
}
