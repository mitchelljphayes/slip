//! Descriptor-confined, root-owned service storage primitive.
//!
//! This module provides the production filesystem layer for managed service
//! data directories (SLIP-106 Part 2). It is **Linux-only**: the trusted
//! absolute root is opened safely from `/` and every descendant operation is
//! descriptor-relative. On non-Linux the types are not constructible.
//!
//! ## Security properties
//!
//! - **Safe root open**: `/` is opened with `openat2` using empty resolve
//!   flags (you cannot confine beneath `/` itself). The configured absolute
//!   root is then opened as relative components beneath the held `/` FD using
//!   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`. Ancestor mount crossings are
//!   permitted because the configured root is administrator-controlled and
//!   commonly lives across a mount boundary (e.g. `/var` on FCOS, a separate
//!   data volume). Kernel support for the stronger descendant flags is probed
//!   by opening `.` relative to the held `/` FD with
//!   `RESOLVE_BENEATH | NO_SYMLINKS | NO_XDEV`; `ENOSYS` fails closed.
//! - **Descendant mount confinement**: every post-root `openat2` (parent
//!   resolution, pgdata validation, secret/file access, and
//!   `ValidatedBindSource::revalidate`) uses the full
//!   `RESOLVE_BENEATH | NO_SYMLINKS | NO_XDEV` so any mount introduced below
//!   the acquired root is rejected with `EXDEV` by the kernel.
//! - **Descriptor-relative mutations**: every multi-component mutation first
//!   opens its parent directory descriptor-confined, then `mkdirat`/
//!   `renameat`/`unlinkat`/`statat` operates on a single validated basename.
//!   No multi-component path is ever passed to a mutating syscall.
//! - **Exact UID/mode/device/type/inode checks** on every opened directory
//!   and file. Exclusive creates use `O_EXCL | O_NOFOLLOW`.
//! - **`ValidatedBindSource` token**: verifies file type/UID/mode/device/inode
//!   before construction, holds duplicated FDs, revalidates with
//!   file-appropriate flags. Documented as a snapshot, not race-eliminating.
//! - **Never recursively delete**. `unlink_descendant_dir` removes a single
//!   empty directory via `unlinkat(AT_REMOVEDIR)`.
//! - **No unsafe borrowed-FD ownership**: `fd_into_file` consumes an
//!   `OwnedFd` via `into_raw_fd` + `File::from_raw_fd`.

use std::io;
use std::path::PathBuf;

// ─── Non-Linux: unconstructible stubs ────────────────────────────────────────

/// Errors from the secure service storage primitive.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The platform or kernel does not support `openat2` (Linux < 5.6 or
    /// non-Linux). Service storage is production-only on Linux rootful Podman.
    #[error(
        "secure service storage requires openat2 (Linux 5.6+); this platform/kernel is unsupported"
    )]
    UnsupportedPlatform,
    /// The root path does not exist or is not a directory.
    #[error("service storage root not found or not a directory: {0}")]
    RootNotFound(PathBuf),
    /// The root or a child has the wrong owner (must be the expected UID).
    #[error("ownership mismatch: expected UID {expected}, got {actual} for {path}")]
    WrongOwner {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    /// The root or a child has the wrong mode.
    #[error("mode mismatch: expected {expected:o}, got {actual:o} for {path}")]
    WrongMode {
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    /// The root or a child is on the wrong device (mount substitution).
    #[error("device mismatch: expected {expected}, got {actual} for {path}")]
    WrongDevice {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    /// The root or a child is the wrong file type.
    #[error("file type mismatch: expected {expected}, got {actual} for {path}")]
    WrongType {
        path: PathBuf,
        expected: &'static str,
        actual: &'static str,
    },
    /// The inode changed between validation and revalidation (TOCTOU).
    #[error("inode mismatch for {path}: expected {expected}, got {actual} (TOCTOU substitution)")]
    InodeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    /// A symlink was encountered where a real directory/file was expected.
    #[error("symlink rejected at {0} (NO_SYMLINKS/NOFOLLOW enforced)")]
    SymlinkRejected(PathBuf),
    /// A path component attempted to escape the confined root.
    #[error("path escapes the confined root: {0}")]
    EscapesRoot(PathBuf),
    /// A mount-point crossing was attempted.
    #[error("mount-point crossing rejected: {0}")]
    CrossDevice(PathBuf),
    /// An exclusive create found an existing entry.
    #[error("exclusive create failed (entry exists): {0}")]
    AlreadyExists(PathBuf),
    /// A path was not found.
    #[error("not found: {0}")]
    NotFound(PathBuf),
    /// An I/O error from the kernel.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// An empty relative path or invalid component was supplied.
    #[error("invalid relative path component: {0}")]
    InvalidComponent(String),
}

/// The kind of filesystem object a [`ValidatedBindSource`] refers to.
///
/// Used to select file-appropriate `openat2` flags during revalidation:
/// directories use `DIRECTORY | NOFOLLOW`, files use `NOFOLLOW`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindObjectKind {
    Directory,
    File,
}

impl BindObjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
        }
    }
}

// On non-Linux, ServiceStorage and ValidatedBindSource are empty enums so
// they cannot be constructed.
#[cfg(not(target_os = "linux"))]
mod _non_linux {
    use super::{BindObjectKind, StorageError};

    /// Linux-only production storage. On non-Linux this is an empty enum and
    /// cannot be constructed.
    #[derive(Debug)]
    pub enum ServiceStorage {}

    /// Linux-only bind-source trust token. On non-Linux this is an empty enum
    /// and cannot be constructed.
    #[derive(Debug, Clone)]
    pub enum ValidatedBindSource {}

    impl ServiceStorage {
        pub fn new(_root: &std::path::Path) -> Result<Self, StorageError> {
            Err(StorageError::UnsupportedPlatform)
        }
    }

    impl ValidatedBindSource {
        pub fn revalidate(&self) -> Result<(), StorageError> {
            match *self {}
        }
        pub fn canonical_path(&self) -> &std::path::Path {
            match *self {}
        }
        pub fn object_kind(&self) -> BindObjectKind {
            match *self {}
        }
        pub fn uid(&self) -> u32 {
            match *self {}
        }
        pub fn mode(&self) -> u32 {
            match *self {}
        }
        pub fn device(&self) -> u64 {
            match *self {}
        }
        pub fn inode(&self) -> u64 {
            match *self {}
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use _non_linux::{ServiceStorage, ValidatedBindSource};

// ─── Linux implementation ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod _linux {
    use std::ffi::CString;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};
    use std::path::{Path, PathBuf};

    use rustix::fd::BorrowedFd;
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, mkdirat, openat2, statat,
    };
    use rustix::io::Errno;

    use super::{BindObjectKind, StorageError};

    /// Resolve flags for **trusted configured-root acquisition** from the
    /// held `/` FD. Permits ancestor mount crossings (`/var` is a separate
    /// mount on FCOS and the configured root commonly lives across it) but
    /// still forbids symlinks and escapes beneath `/`.
    ///
    /// The configured absolute path is administrator-controlled. Omitting
    /// `NO_XDEV` here does not let an unprivileged actor create or adopt a
    /// UID-0, mode-0700 root or mount a filesystem; those require
    /// privileges. `from_root_fd` independently `fstat`s the opened object
    /// and requires a real directory, UID 0, and exact mode 0700 before
    /// adoption.
    const ROOT_RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_SYMLINKS);

    /// Resolve flags for **every descendant operation** beneath the acquired
    /// trusted root FD. Adds `NO_XDEV` so any mount introduced below the root
    /// (including a same-superblock bind mount) is rejected with `EXDEV` by
    /// the kernel.
    const DESCENDANT_RESOLVE_FLAGS: ResolveFlags = ROOT_RESOLVE_FLAGS.union(ResolveFlags::NO_XDEV);

    /// Expected UID for production root-owned storage.
    const EXPECTED_UID: u32 = 0;
    /// Expected mode for service directories.
    const DIR_MODE: u32 = 0o700;
    /// Expected mode for secret files.
    const FILE_MODE: u32 = 0o600;
    /// Expected mode for the postgres `pgdata` child directory. This is the
    /// only exception to the 0700 policy: the postgres entrypoint's `gosu
    /// postgres` re-run needs to traverse the mount root, which requires
    /// 0755 so UID 999 can search the directory. The 0700 parent (data dir
    /// root) holds the bootstrap marker and is never mounted.
    const PGDATA_DIR_MODE: u32 = 0o755;

    /// Descriptor-confined, root-owned service storage primitive.
    ///
    /// The trusted root is opened once at construction. `/` is opened safely
    /// with empty resolve flags, then the configured absolute root is opened
    /// as relative components beneath the held `/` FD using
    /// `RESOLVE_BENEATH | NO_SYMLINKS` (without `NO_XDEV`, permitting ancestor
    /// mount crossings; the configured root is administrator-controlled).
    /// All descendant operations are relative to that held root FD and use
    /// the full `RESOLVE_BENEATH | NO_SYMLINKS | NO_XDEV` so any mount below
    /// the acquired root is rejected.
    // In production builds the derived Debug is sound: all fields are Debug.
    // In test builds the #[cfg(test)] fsync_fault_hook field is a
    // `Mutex<Option<Box<dyn Fn...>>>` and `dyn Fn` is not Debug, so we supply
    // a manual Debug impl below that omits the hook and the raw root_fd
    // handle (never printing kernel descriptor state or test injection
    // internals). Both paths keep Debug available so call sites that
    // Debug-format a ServiceStorage compile in all build modes.
    #[cfg_attr(not(test), derive(Debug))]
    pub struct ServiceStorage {
        root_fd: OwnedFd,
        root_path: PathBuf,
        root_dev: u64,
        #[allow(dead_code)]
        root_ino: u64,
        /// Test-only fault injector for `fsync_descendant_dir`. In production
        /// this is always None. When set, the hook is called with the relative
        /// path; if it returns `Err`, `fsync_descendant_dir` returns that error
        /// instead of performing the real fsync.
        #[cfg(test)]
        #[allow(clippy::type_complexity)]
        fsync_fault_hook:
            std::sync::Mutex<Option<Box<dyn Fn(&str) -> Result<(), StorageError> + Send + Sync>>>,
    }

    #[cfg(test)]
    impl std::fmt::Debug for ServiceStorage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Omit root_fd (raw kernel descriptor) and the test-only fault
            // hook (dyn Fn is not Debug and carries no secret material).
            // root_path/root_dev/root_ino are diagnostics-safe (the trusted
            // root identity, not secret bytes).
            f.debug_struct("ServiceStorage")
                .field("root_path", &self.root_path)
                .field("root_dev", &self.root_dev)
                .field("root_ino", &self.root_ino)
                .finish_non_exhaustive()
        }
    }

    impl ServiceStorage {
        /// Open and validate the trusted root.
        ///
        /// `/` is opened with `openat2` and empty resolve flags (you cannot
        /// confine beneath `/` itself). Kernel support for descendant
        /// enforcement is probed by opening `.` relative to the held `/` FD
        /// with `RESOLVE_BENEATH | NO_SYMLINKS | NO_XDEV`; `ENOSYS` fails
        /// closed. The configured absolute root is then opened as relative
        /// components beneath the held `/` FD using
        /// `RESOLVE_BENEATH | NO_SYMLINKS` (without `NO_XDEV`). Ancestor
        /// mount crossings are permitted because the configured root is
        /// administrator-controlled and commonly lives across a mount
        /// boundary (e.g. `/var` on FCOS, a separate data volume).
        ///
        /// The root must exist, be a directory, owned by UID 0, and have mode
        /// 0700. `from_root_fd` `fstat`s the opened object and enforces this
        /// before adoption. Once the trusted root FD is acquired, every
        /// descendant `openat2` uses the full descendant flags including
        /// `NO_XDEV`, so mounts below the root are rejected.
        pub fn new(root: &Path) -> Result<Self, StorageError> {
            if !root.is_absolute() {
                return Err(StorageError::EscapesRoot(root.to_path_buf()));
            }

            // Open `/` safely. We cannot use RESOLVE_BENEATH on `/` itself
            // because there is nothing beneath `/`. Use empty resolve flags.
            let slash_fd = openat2(
                rustix::fs::CWD,
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::empty(),
            )
            .map_err(|e| {
                if e == Errno::NOSYS {
                    StorageError::UnsupportedPlatform
                } else {
                    StorageError::Io(e.into())
                }
            })?;

            // Probe openat2 + descendant flags by opening "." relative to
            // the held "/" FD. ENOSYS means the kernel does not support
            // openat2 at all (or does not support the descendant resolve
            // flags). This proves the kernel can enforce NO_XDEV on
            // descendant operations, which is the stronger requirement.
            let probe = openat2(
                &slash_fd,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                DESCENDANT_RESOLVE_FLAGS,
            );
            match probe {
                Ok(_probe_fd) => { /* full flags supported */ }
                Err(Errno::NOSYS) => return Err(StorageError::UnsupportedPlatform),
                Err(e) => return Err(StorageError::Io(e.into())),
            }

            // The configured root is absolute. Strip the leading '/' and
            // open the relative remainder beneath the held "/" FD using
            // ROOT_RESOLVE_FLAGS (without NO_XDEV; ancestor mount crossings
            // are permitted for the administrator-controlled configured root).
            // If the root IS "/", use slash_fd directly.
            let rel = root
                .strip_prefix("/")
                .map_err(|_| StorageError::EscapesRoot(root.to_path_buf()))?;
            let rel_str = rel
                .to_str()
                .ok_or_else(|| StorageError::EscapesRoot(root.to_path_buf()))?;
            if rel_str.is_empty() {
                return Self::from_root_fd(slash_fd, root.to_path_buf());
            }
            // Validate the relative path before passing it to the kernel.
            validate_relative(rel_str)?;
            let rel_cstr =
                CString::new(rel_str).map_err(|_| StorageError::EscapesRoot(root.to_path_buf()))?;
            // Open the configured root relative to the held "/" FD using
            // ROOT_RESOLVE_FLAGS (without NO_XDEV). The configured absolute
            // path is administrator-controlled and may legitimately cross a
            // mount boundary (e.g. /var on FCOS, a separate data volume).
            // BENEATH still prevents escape beneath "/", NO_SYMLINKS still
            // rejects symlinks in ancestors and the final component, and
            // from_root_fd fstats the opened object requiring a real
            // directory, UID 0, and exact mode 0700 before adoption.
            let root_fd = openat2(
                &slash_fd,
                &rel_cstr,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ROOT_RESOLVE_FLAGS,
            )
            .map_err(|e| map_openat2_err(e, root))?;

            Self::from_root_fd(root_fd, root.to_path_buf())
        }

        fn from_root_fd(root_fd: OwnedFd, root_path: PathBuf) -> Result<Self, StorageError> {
            let st = fstat(&root_fd).map_err(|e| StorageError::Io(e.into()))?;
            verify_dir_identity(&st, &root_path, EXPECTED_UID, DIR_MODE)?;
            Ok(Self {
                root_fd,
                root_path,
                root_dev: st.st_dev,
                root_ino: st.st_ino,
                #[cfg(test)]
                fsync_fault_hook: std::sync::Mutex::new(None),
            })
        }

        /// The canonical absolute path of the root (diagnostics only).
        pub fn root_path(&self) -> &Path {
            &self.root_path
        }

        /// Open a descendant directory relative to the held root FD. For
        /// multi-component paths, each intermediate component is opened
        /// descriptor-relative and verified. The final directory is verified
        /// to be a directory owned by UID 0 with mode 0700, on the same
        /// device as the root.
        pub fn open_descendant_dir(&self, rel: &str) -> Result<OwnedFd, StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            let fd = openat2(
                &parent_fd,
                &cstr,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                DESCENDANT_RESOLVE_FLAGS,
            )
            .map_err(|e| map_openat2_err(e, &self.root_path.join(rel)))?;
            let st = fstat(&fd).map_err(|e| StorageError::Io(e.into()))?;
            verify_dir_identity(&st, &self.root_path.join(rel), EXPECTED_UID, DIR_MODE)?;
            verify_same_device(&st, self.root_dev, &self.root_path.join(rel))?;
            Ok(fd)
        }

        /// Create a descendant directory. For multi-component paths, the
        /// parent is opened descriptor-confined first, then `mkdirat`
        /// operates on a single validated basename.
        pub fn create_descendant_dir(&self, rel: &str) -> Result<OwnedFd, StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            mkdirat(&parent_fd, &cstr, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                .map_err(|e| map_mkdir_err(e, &self.root_path.join(rel)))?;
            // Open and verify the created directory.
            self.open_descendant_dir(rel)
        }

        /// Open a service directory `<root>/<name>`.
        pub fn open_service_dir(
            &self,
            name: &crate::services::name::ServiceName,
        ) -> Result<OwnedFd, StorageError> {
            self.open_descendant_dir(name.as_str())
        }

        /// Create a service directory `<root>/<name>` with mode 0700.
        pub fn create_service_dir(
            &self,
            name: &crate::services::name::ServiceName,
        ) -> Result<OwnedFd, StorageError> {
            self.create_descendant_dir(name.as_str())
        }

        /// Create a `pgdata` child directory inside an existing service
        /// data directory, with mode 0755 (not the default 0700). This is
        /// a narrow policy exception for the postgres provider: the
        /// entrypoint's `gosu postgres` re-run needs to traverse the mount
        /// root, which requires 0755 so UID 999 can search the directory.
        ///
        /// The parent (`<root>/<parent>`) must already exist as a verified
        /// 0700 root-owned directory. The child (`<root>/<parent>/pgdata`)
        /// is created via descriptor-relative `mkdirat` with mode 0755,
        /// then opened with `openat2(RESOLVE_BENEATH|NO_SYMLINKS|NO_XDEV)`
        /// and `fstat`-verified: real directory, UID 0, exact mode 0755,
        /// same device. On `AlreadyExists`, the existing directory is
        /// validated rather than accepted blindly.
        ///
        /// Returns a `ValidatedBindSource` token carrying the verified
        /// identity (UID, mode, device, inode) for later revalidation
        /// before the runtime create call.
        pub fn create_pgdata_child(
            &self,
            parent_rel: &str,
            child_name: &str,
        ) -> Result<ValidatedBindSource, StorageError> {
            // Validate the child name: no path components, no traversal.
            validate_relative(child_name)?;
            if child_name.contains('/') {
                return Err(StorageError::InvalidComponent(
                    "pgdata child name must be a single component".to_string(),
                ));
            }

            let child_rel = format!("{parent_rel}/{child_name}");

            // Try to create the directory with mode 0755. If it already
            // exists, fall through to validation.
            let (parent_fd, basename) = self.resolve_parent(&child_rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            match mkdirat(
                &parent_fd,
                &cstr,
                Mode::RUSR
                    | Mode::WUSR
                    | Mode::XUSR
                    | Mode::RGRP
                    | Mode::XGRP
                    | Mode::ROTH
                    | Mode::XOTH,
            ) {
                Ok(()) => {}
                Err(Errno::EXIST) => {
                    // Already exists: validate below.
                }
                Err(e) => return Err(map_mkdir_err(e, &self.root_path.join(&child_rel))),
            }

            // Open and verify the child directory with the 0755 policy.
            // We use a dedicated verification path rather than
            // open_descendant_dir (which checks 0700).
            let cstr2 = CString::new(child_rel.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(child_rel.clone()))?;
            let fd = openat2(
                &self.root_fd,
                &cstr2,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                DESCENDANT_RESOLVE_FLAGS,
            )
            .map_err(|e| map_openat2_err(e, &self.root_path.join(&child_rel)))?;
            let st = fstat(&fd).map_err(|e| StorageError::Io(e.into()))?;
            verify_dir_identity(
                &st,
                &self.root_path.join(&child_rel),
                EXPECTED_UID,
                PGDATA_DIR_MODE,
            )?;
            verify_same_device(&st, self.root_dev, &self.root_path.join(&child_rel))?;

            ValidatedBindSource::new_with_mode(
                fd,
                &self.root_fd,
                &self.root_path,
                &child_rel,
                BindObjectKind::Directory,
                PGDATA_DIR_MODE,
            )
        }

        /// Validate and create a [`ValidatedBindSource`] token for a
        /// descendant directory. The directory must exist and pass identity
        /// checks (type=directory, UID 0, mode 0700, same device). The token
        /// is constructed only after verification.
        pub fn validate_bind_source_dir(
            &self,
            rel: &str,
        ) -> Result<ValidatedBindSource, StorageError> {
            let fd = self.open_descendant_dir(rel)?;
            // open_descendant_dir already verified type/UID/mode/device.
            // Construct the token with the verified identity.
            ValidatedBindSource::new(
                fd,
                &self.root_fd,
                &self.root_path,
                rel,
                BindObjectKind::Directory,
            )
        }

        /// Validate and create a [`ValidatedBindSource`] token for a
        /// descendant file. The file must exist and pass identity checks
        /// (type=regular file, UID 0, mode 0600, same device). The token is
        /// constructed only after verification.
        pub fn validate_bind_source_file(
            &self,
            rel: &str,
        ) -> Result<ValidatedBindSource, StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            let fd = openat2(
                &parent_fd,
                &cstr,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                DESCENDANT_RESOLVE_FLAGS,
            )
            .map_err(|e| map_openat2_err(e, &self.root_path.join(rel)))?;
            let st = fstat(&fd).map_err(|e| StorageError::Io(e.into()))?;
            verify_file_identity(&st, &self.root_path.join(rel), EXPECTED_UID, FILE_MODE)?;
            verify_same_device(&st, self.root_dev, &self.root_path.join(rel))?;
            ValidatedBindSource::new(
                fd,
                &self.root_fd,
                &self.root_path,
                rel,
                BindObjectKind::File,
            )
        }

        /// Read a descendant file. The file is opened with `NOFOLLOW` and
        /// full resolve flags, and its identity is verified before reading.
        pub fn read_file(&self, rel: &str, max_bytes: usize) -> Result<Vec<u8>, StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            let fd = openat2(
                &parent_fd,
                &cstr,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                DESCENDANT_RESOLVE_FLAGS,
            )
            .map_err(|e| map_openat2_err(e, &self.root_path.join(rel)))?;
            let st = fstat(&fd).map_err(|e| StorageError::Io(e.into()))?;
            verify_file_identity(&st, &self.root_path.join(rel), EXPECTED_UID, FILE_MODE)?;
            verify_same_device(&st, self.root_dev, &self.root_path.join(rel))?;
            if (st.st_size as usize) > max_bytes {
                return Err(StorageError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "file {} size {} exceeds max {}",
                        self.root_path.join(rel).display(),
                        st.st_size,
                        max_bytes
                    ),
                )));
            }
            let file = fd_into_file(fd)?;
            read_to_end_capped(file, max_bytes)
        }

        /// Write a descendant file with `O_EXCL | O_NOFOLLOW` and mode 0600,
        /// then `fstat`, `write_all`, and `fsync`. The parent directory is
        /// opened descriptor-confined first.
        pub fn write_file_exclusive(&self, rel: &str, data: &[u8]) -> Result<(), StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            let fd = openat2(
                &parent_fd,
                &cstr,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
                DESCENDANT_RESOLVE_FLAGS,
            )
            .map_err(|e| map_openat2_err(e, &self.root_path.join(rel)))?;
            let st = fstat(&fd).map_err(|e| StorageError::Io(e.into()))?;
            verify_file_identity(&st, &self.root_path.join(rel), EXPECTED_UID, FILE_MODE)?;
            verify_same_device(&st, self.root_dev, &self.root_path.join(rel))?;
            let file = fd_into_file(fd)?;
            write_all_and_fsync(&file, data)?;
            Ok(())
        }

        /// Atomically rename a descendant `from` to `to`. Both paths must be
        /// relative and confined beneath the root. The parent of `to` must
        /// exist. For same-parent renames, a single held parent FD is used
        /// for both `renameat` operands.
        pub fn rename_descendant(&self, from: &str, to: &str) -> Result<(), StorageError> {
            let (from_parent_fd, from_base) = self.resolve_parent(from)?;
            let (to_parent_fd, to_base) = self.resolve_parent(to)?;
            let from_cstr = CString::new(from_base.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(from_base.clone()))?;
            let to_cstr = CString::new(to_base.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(to_base.clone()))?;
            rustix::fs::renameat(&from_parent_fd, &from_cstr, &to_parent_fd, &to_cstr)
                .map_err(|e| StorageError::Io(e.into()))?;
            Ok(())
        }

        /// Unlink a descendant file using `unlinkat` with `AtFlags::empty()`.
        /// The parent directory is opened descriptor-confined first (with
        /// `RESOLVE_NO_SYMLINKS`), then `unlinkat` operates on a single
        /// validated basename. `empty()` flags means the target is unlinked
        /// as a file (or symlink); `unlinkat` on a directory returns
        /// `EISDIR`. Does not remove directories.
        pub fn unlink_descendant(&self, rel: &str) -> Result<(), StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            rustix::fs::unlinkat(&parent_fd, &cstr, AtFlags::empty())
                .map_err(|e| map_unlink_err(e, &self.root_path.join(rel)))?;
            Ok(())
        }

        /// Remove a descendant empty directory using `unlinkat` with
        /// `AT_REMOVEDIR`. The parent directory is opened descriptor-confined
        /// first. The directory must be empty.
        pub fn unlink_descendant_dir(&self, rel: &str) -> Result<(), StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            rustix::fs::unlinkat(&parent_fd, &cstr, AtFlags::REMOVEDIR)
                .map_err(|e| map_unlink_dir_err(e, &self.root_path.join(rel)))?;
            Ok(())
        }

        /// Fsync the held root directory.
        pub fn fsync_root(&self) -> Result<(), StorageError> {
            rustix::fs::fsync(&self.root_fd).map_err(|e| StorageError::Io(e.into()))
        }

        /// Open a descendant directory, fsync it, and drop the FD. Used to
        /// durably persist a rename into a parent directory.
        pub fn fsync_descendant_dir(&self, rel: &str) -> Result<(), StorageError> {
            // Test-only fault injection: if a hook is set, call it instead
            // of performing the real fsync. This allows testing that callers
            // propagate fsync failures correctly.
            #[cfg(test)]
            {
                if let Some(hook) = self.fsync_fault_hook.lock().unwrap().as_ref() {
                    return hook(rel);
                }
            }
            let fd = self.open_descendant_dir_raw(rel)?;
            rustix::fs::fsync(&fd).map_err(|e| StorageError::Io(e.into()))
        }

        /// Set a test-only fault hook for `fsync_descendant_dir`. When set,
        /// the hook is called with the relative path instead of performing
        /// the real fsync. If the hook returns `Err`, that error is returned
        /// to the caller. This is only available in test builds.
        #[cfg(test)]
        pub fn set_fsync_fault_hook<F>(&self, hook: F)
        where
            F: Fn(&str) -> Result<(), StorageError> + Send + Sync + 'static,
        {
            *self.fsync_fault_hook.lock().unwrap() = Some(Box::new(hook));
        }

        /// Open a descendant directory raw (without the 0700 mode check).
        /// Verifies directory type, UID, and device.
        fn open_descendant_dir_raw(&self, rel: &str) -> Result<OwnedFd, StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            let fd = openat2(
                &parent_fd,
                &cstr,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                DESCENDANT_RESOLVE_FLAGS,
            )
            .map_err(|e| map_openat2_err(e, &self.root_path.join(rel)))?;
            let st = fstat(&fd).map_err(|e| StorageError::Io(e.into()))?;
            let ft = FileType::from_raw_mode(st.st_mode);
            if ft != FileType::Directory {
                return Err(StorageError::WrongType {
                    path: self.root_path.join(rel),
                    expected: "directory",
                    actual: file_type_name(ft),
                });
            }
            if st.st_uid != EXPECTED_UID {
                return Err(StorageError::WrongOwner {
                    path: self.root_path.join(rel),
                    expected: EXPECTED_UID,
                    actual: st.st_uid,
                });
            }
            verify_same_device(&st, self.root_dev, &self.root_path.join(rel))?;
            Ok(fd)
        }

        /// Stat a descendant path (no follow) relative to the held root.
        pub fn stat_descendant_no_follow(&self, rel: &str) -> Result<Stat, StorageError> {
            let (parent_fd, basename) = self.resolve_parent(rel)?;
            let cstr = CString::new(basename.as_bytes())
                .map_err(|_| StorageError::InvalidComponent(basename.clone()))?;
            statat(&parent_fd, &cstr, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| map_stat_err(e, &self.root_path.join(rel)))
        }

        /// Resolve a relative path to `(parent_fd, basename)`. For
        /// single-component paths, the parent is the root FD. For
        /// multi-component paths, each intermediate directory is opened
        /// descriptor-relative and verified (type=directory, UID 0, mode
        /// 0700, same device). The returned `parent_fd` owns the final
        /// parent directory descriptor.
        fn resolve_parent(&self, rel: &str) -> Result<(OwnedFd, String), StorageError> {
            validate_relative(rel)?;
            // If single component, parent is the root.
            if let Some(last_slash) = rel.rfind('/') {
                let parent_rel = &rel[..last_slash];
                let basename = &rel[last_slash + 1..];
                if basename.is_empty() {
                    return Err(StorageError::InvalidComponent("trailing slash".to_string()));
                }
                let parent_fd = self.open_descendant_dir(parent_rel)?;
                Ok((parent_fd, basename.to_string()))
            } else {
                // Single component: parent is root.
                Ok((self.root_fd_try_clone()?, rel.to_string()))
            }
        }

        /// Duplicate the root FD so the caller can own a copy. Used when
        /// a single-component operation needs a parent FD with the same
        /// lifetime as the operation.
        fn root_fd_try_clone(&self) -> Result<OwnedFd, StorageError> {
            dup_fd(self.root_fd.as_fd())
        }
    }

    /// A validated bind-mount source token.
    ///
    /// Created only by [`ServiceStorage`] from a held descriptor's verified
    /// identity. The token records the object kind and holds duplicated
    /// root/source identity FDs. It provides an immediate
    /// [`revalidate`](Self::revalidate) method using file-appropriate
    /// `openat2` flags.
    ///
    /// **The token proves identity at revalidation time; it does not
    /// eliminate the later daemon mount race.** A daemon consuming the token
    /// for a real mount still requires immediate revalidation at the trusted
    /// root boundary (Part 3). This type does not overclaim race elimination.
    #[derive(Debug)]
    pub struct ValidatedBindSource {
        #[allow(dead_code)]
        source_fd: OwnedFd,
        root_fd: OwnedFd,
        canonical_path: PathBuf,
        rel: String,
        expected_kind: BindObjectKind,
        uid: u32,
        mode: u32,
        device: u64,
        inode: u64,
    }

    impl ValidatedBindSource {
        fn new(
            source_fd: OwnedFd,
            root_fd: &OwnedFd,
            root_path: &Path,
            rel: &str,
            kind: BindObjectKind,
        ) -> Result<Self, StorageError> {
            let expected_mode = match kind {
                BindObjectKind::Directory => DIR_MODE,
                BindObjectKind::File => FILE_MODE,
            };
            Self::new_with_mode(source_fd, root_fd, root_path, rel, kind, expected_mode)
        }

        /// Construct a token with an explicit expected mode. Used by
        /// `create_pgdata_child` which requires 0755 instead of the default
        /// 0700. The caller must have already verified the identity via
        /// `verify_dir_identity` / `verify_file_identity` with the same
        /// mode; this constructor re-checks to fail closed on any
        /// discrepancy.
        fn new_with_mode(
            source_fd: OwnedFd,
            root_fd: &OwnedFd,
            root_path: &Path,
            rel: &str,
            kind: BindObjectKind,
            expected_mode: u32,
        ) -> Result<Self, StorageError> {
            let root_dup = dup_fd(root_fd.as_fd())?;
            let st = fstat(&source_fd).map_err(|e| StorageError::Io(e.into()))?;
            // Verify file type matches expected kind before token creation.
            let ft = FileType::from_raw_mode(st.st_mode);
            match (kind, ft) {
                (BindObjectKind::Directory, FileType::Directory) => {}
                (BindObjectKind::File, FileType::RegularFile) => {}
                _ => {
                    return Err(StorageError::WrongType {
                        path: root_path.join(rel),
                        expected: kind.as_str(),
                        actual: file_type_name(ft),
                    });
                }
            }
            // Verify UID.
            if st.st_uid != EXPECTED_UID {
                return Err(StorageError::WrongOwner {
                    path: root_path.join(rel),
                    expected: EXPECTED_UID,
                    actual: st.st_uid,
                });
            }
            // Verify mode.
            if (st.st_mode & 0o7777) != expected_mode {
                return Err(StorageError::WrongMode {
                    path: root_path.join(rel),
                    expected: expected_mode,
                    actual: st.st_mode & 0o7777,
                });
            }
            Ok(Self {
                source_fd,
                root_fd: root_dup,
                canonical_path: root_path.join(rel),
                rel: rel.to_string(),
                expected_kind: kind,
                uid: st.st_uid,
                mode: st.st_mode & 0o7777,
                device: st.st_dev,
                inode: st.st_ino,
            })
        }

        /// Revalidate that the source still matches the recorded identity
        /// (type, UID, mode, device, inode). Uses file-appropriate `openat2`
        /// flags: `DIRECTORY | NOFOLLOW` for directories, `NOFOLLOW` for
        /// files. Confined beneath the held root FD.
        ///
        /// **This proves identity at revalidation time only.** A daemon
        /// consuming the token for a real mount must revalidate again
        /// immediately before the mount at the trusted root boundary
        /// (Part 3). This method does not eliminate the mount race.
        pub fn revalidate(&self) -> Result<(), StorageError> {
            let cstr = CString::new(self.rel.as_str())
                .map_err(|_| StorageError::InvalidComponent(self.rel.clone()))?;
            let flags = match self.expected_kind {
                BindObjectKind::Directory => {
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
                }
                BindObjectKind::File => OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            };
            let fd = openat2(
                &self.root_fd,
                &cstr,
                flags,
                Mode::empty(),
                DESCENDANT_RESOLVE_FLAGS,
            )
            .map_err(|e| map_openat2_err(e, &self.canonical_path))?;
            let st = fstat(&fd).map_err(|e| StorageError::Io(e.into()))?;

            let ft = FileType::from_raw_mode(st.st_mode);
            let actual_kind = match (self.expected_kind, ft) {
                (BindObjectKind::Directory, FileType::Directory) => BindObjectKind::Directory,
                (BindObjectKind::File, FileType::RegularFile) => BindObjectKind::File,
                _ => {
                    return Err(StorageError::WrongType {
                        path: self.canonical_path.clone(),
                        expected: self.expected_kind.as_str(),
                        actual: file_type_name(ft),
                    });
                }
            };
            let _ = actual_kind;

            if st.st_uid != self.uid {
                return Err(StorageError::WrongOwner {
                    path: self.canonical_path.clone(),
                    expected: self.uid,
                    actual: st.st_uid,
                });
            }
            if (st.st_mode & 0o7777) != self.mode {
                return Err(StorageError::WrongMode {
                    path: self.canonical_path.clone(),
                    expected: self.mode,
                    actual: st.st_mode & 0o7777,
                });
            }
            if st.st_dev != self.device {
                return Err(StorageError::WrongDevice {
                    path: self.canonical_path.clone(),
                    expected: self.device,
                    actual: st.st_dev,
                });
            }
            if st.st_ino != self.inode {
                return Err(StorageError::InodeMismatch {
                    path: self.canonical_path.clone(),
                    expected: self.inode,
                    actual: st.st_ino,
                });
            }
            Ok(())
        }

        pub fn canonical_path(&self) -> &Path {
            &self.canonical_path
        }

        pub fn object_kind(&self) -> BindObjectKind {
            self.expected_kind
        }

        pub fn uid(&self) -> u32 {
            self.uid
        }
        pub fn mode(&self) -> u32 {
            self.mode
        }
        pub fn device(&self) -> u64 {
            self.device
        }
        pub fn inode(&self) -> u64 {
            self.inode
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    /// Validate a relative path: no leading `/`, no `..`, no `.` components,
    /// no empty components, no NUL, no trailing slash.
    fn validate_relative(rel: &str) -> Result<(), StorageError> {
        if rel.is_empty() {
            return Err(StorageError::InvalidComponent("empty path".to_string()));
        }
        if rel.starts_with('/') {
            return Err(StorageError::EscapesRoot(PathBuf::from(rel)));
        }
        if rel.contains('\0') {
            return Err(StorageError::InvalidComponent("contains NUL".to_string()));
        }
        if rel.ends_with('/') {
            return Err(StorageError::InvalidComponent("trailing slash".to_string()));
        }
        for component in rel.split('/') {
            if component.is_empty() {
                return Err(StorageError::InvalidComponent(
                    "empty component".to_string(),
                ));
            }
            if component == ".." {
                return Err(StorageError::EscapesRoot(PathBuf::from(rel)));
            }
            if component == "." {
                return Err(StorageError::InvalidComponent("'.' component".to_string()));
            }
        }
        Ok(())
    }

    fn verify_dir_identity(
        st: &Stat,
        path: &Path,
        expected_uid: u32,
        expected_mode: u32,
    ) -> Result<(), StorageError> {
        let ft = FileType::from_raw_mode(st.st_mode);
        if ft != FileType::Directory {
            return Err(StorageError::WrongType {
                path: path.to_path_buf(),
                expected: "directory",
                actual: file_type_name(ft),
            });
        }
        if st.st_uid != expected_uid {
            return Err(StorageError::WrongOwner {
                path: path.to_path_buf(),
                expected: expected_uid,
                actual: st.st_uid,
            });
        }
        if (st.st_mode & 0o7777) != expected_mode {
            return Err(StorageError::WrongMode {
                path: path.to_path_buf(),
                expected: expected_mode,
                actual: st.st_mode & 0o7777,
            });
        }
        Ok(())
    }

    fn verify_file_identity(
        st: &Stat,
        path: &Path,
        expected_uid: u32,
        expected_mode: u32,
    ) -> Result<(), StorageError> {
        let ft = FileType::from_raw_mode(st.st_mode);
        if ft != FileType::RegularFile {
            return Err(StorageError::WrongType {
                path: path.to_path_buf(),
                expected: "regular file",
                actual: file_type_name(ft),
            });
        }
        if st.st_uid != expected_uid {
            return Err(StorageError::WrongOwner {
                path: path.to_path_buf(),
                expected: expected_uid,
                actual: st.st_uid,
            });
        }
        if (st.st_mode & 0o7777) != expected_mode {
            return Err(StorageError::WrongMode {
                path: path.to_path_buf(),
                expected: expected_mode,
                actual: st.st_mode & 0o7777,
            });
        }
        Ok(())
    }

    fn verify_same_device(st: &Stat, expected_dev: u64, path: &Path) -> Result<(), StorageError> {
        if st.st_dev != expected_dev {
            return Err(StorageError::WrongDevice {
                path: path.to_path_buf(),
                expected: expected_dev,
                actual: st.st_dev,
            });
        }
        Ok(())
    }

    fn map_openat2_err(e: Errno, path: &Path) -> StorageError {
        match e {
            Errno::NOENT => StorageError::NotFound(path.to_path_buf()),
            Errno::XDEV => StorageError::CrossDevice(path.to_path_buf()),
            Errno::LOOP => StorageError::SymlinkRejected(path.to_path_buf()),
            Errno::NOTDIR => StorageError::WrongType {
                path: path.to_path_buf(),
                expected: "directory",
                actual: "not-a-directory",
            },
            Errno::EXIST => StorageError::AlreadyExists(path.to_path_buf()),
            Errno::NOSYS => StorageError::UnsupportedPlatform,
            other => StorageError::Io(other.into()),
        }
    }

    fn map_mkdir_err(e: Errno, path: &Path) -> StorageError {
        map_openat2_err(e, path)
    }

    fn map_unlink_err(e: Errno, path: &Path) -> StorageError {
        match e {
            Errno::NOENT => StorageError::NotFound(path.to_path_buf()),
            Errno::ISDIR => StorageError::WrongType {
                path: path.to_path_buf(),
                expected: "file",
                actual: "directory",
            },
            other => StorageError::Io(other.into()),
        }
    }

    fn map_unlink_dir_err(e: Errno, path: &Path) -> StorageError {
        match e {
            Errno::NOENT => StorageError::NotFound(path.to_path_buf()),
            Errno::NOTEMPTY => StorageError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("directory {} not empty", path.display()),
            )),
            other => StorageError::Io(other.into()),
        }
    }

    fn map_stat_err(e: Errno, path: &Path) -> StorageError {
        match e {
            Errno::NOENT => StorageError::NotFound(path.to_path_buf()),
            other => StorageError::Io(other.into()),
        }
    }

    fn file_type_name(ft: FileType) -> &'static str {
        match ft {
            FileType::RegularFile => "regular file",
            FileType::Directory => "directory",
            FileType::Symlink => "symlink",
            FileType::Fifo => "fifo",
            FileType::Socket => "socket",
            FileType::CharacterDevice => "character device",
            FileType::BlockDevice => "block device",
            FileType::Unknown => "unknown",
        }
    }

    /// Duplicate a borrowed FD into an `OwnedFd` via `fcntl_dupfd_cloexec`.
    pub(crate) fn dup_fd(fd: BorrowedFd) -> Result<OwnedFd, StorageError> {
        rustix::io::fcntl_dupfd_cloexec(fd, 0).map_err(|e| StorageError::Io(e.into()))
    }

    /// Convert an `OwnedFd` into an owning `File` via `into_raw_fd` +
    /// `File::from_raw_fd`. The `File` owns the FD and closes it on drop.
    pub(crate) fn fd_into_file(fd: OwnedFd) -> Result<File, StorageError> {
        let raw = fd.into_raw_fd();
        // Safety: `raw` is a valid open FD we solely own (transferred from
        // the OwnedFd). `File::from_raw_fd` takes ownership and closes it
        // on drop.
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    pub(crate) fn read_to_end_capped(
        mut file: File,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StorageError> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = file.read(&mut chunk).map_err(StorageError::Io)?;
            if n == 0 {
                break;
            }
            if buf.len() + n > max_bytes {
                return Err(StorageError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("read exceeded max {max_bytes} bytes"),
                )));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        Ok(buf)
    }

    pub(crate) fn write_all_and_fsync(file: &File, data: &[u8]) -> Result<(), StorageError> {
        let mut file = file;
        file.write_all(data).map_err(StorageError::Io)?;
        file.sync_all().map_err(StorageError::Io)?;
        Ok(())
    }

    // ─── Tests (Linux-only) ───────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::services::name::ServiceName;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        fn make_root() -> tempfile::TempDir {
            let d = tempfile::tempdir().unwrap();
            let _ = fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700));
            d
        }

        fn skip_if_nonroot() -> bool {
            rustix::process::getuid().as_raw() != 0
        }

        #[test]
        fn storage_constructor_opens_root() {
            if skip_if_nonroot() {
                eprintln!("skipping (not root)");
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).expect("constructor must open root");
            assert_eq!(s.root_path(), d.path());
        }

        #[test]
        fn storage_rejects_relative_root() {
            let res = ServiceStorage::new(std::path::Path::new("relative/path"));
            assert!(matches!(res, Err(StorageError::EscapesRoot(_))));
        }

        #[test]
        fn storage_create_and_open_service_dir() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            let name = ServiceName::parse("pg").unwrap();
            let _fd = s.create_service_dir(&name).expect("create");
            assert!(s.create_service_dir(&name).is_err());
            let _fd2 = s.open_service_dir(&name).expect("open");
        }

        #[test]
        fn storage_rejects_traversal() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            assert!(matches!(
                s.open_descendant_dir(".."),
                Err(StorageError::EscapesRoot(_))
            ));
            assert!(matches!(
                s.open_descendant_dir("foo/../bar"),
                Err(StorageError::EscapesRoot(_))
            ));
        }

        #[test]
        fn storage_rejects_trailing_slash() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            assert!(matches!(
                s.open_descendant_dir("foo/"),
                Err(StorageError::InvalidComponent(_))
            ));
        }

        #[test]
        fn storage_rejects_dot_component() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            assert!(matches!(
                s.open_descendant_dir("."),
                Err(StorageError::InvalidComponent(_))
            ));
        }

        #[test]
        fn storage_rejects_intermediate_symlink() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let _ = fs::create_dir_all(root.join("real"));
            let _ = fs::set_permissions(root.join("real"), fs::Permissions::from_mode(0o700));
            std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
            let s = ServiceStorage::new(&root).unwrap();
            // openat2 with NO_SYMLINKS rejects the symlink at resolution.
            assert!(s.open_descendant_dir("link/file").is_err());
        }

        #[test]
        fn storage_rejects_symlink_basename() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let _ = fs::create_dir_all(root.join("real"));
            let _ = fs::set_permissions(root.join("real"), fs::Permissions::from_mode(0o700));
            std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
            let s = ServiceStorage::new(&root).unwrap();
            // The symlink itself as the basename: openat2 with NOFOLLOW
            // rejects it (O_DIRECTORY on a symlink fails).
            assert!(s.open_descendant_dir("link").is_err());
        }

        #[test]
        fn storage_write_and_read_file() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            let name = ServiceName::parse("pg").unwrap();
            let _ = s.create_service_dir(&name).unwrap();
            s.write_file_exclusive("pg/secret", b"hello world").unwrap();
            let buf = s.read_file("pg/secret", 1024).unwrap();
            assert_eq!(buf, b"hello world");
            assert!(s.write_file_exclusive("pg/secret", b"again").is_err());
        }

        #[test]
        fn storage_validate_bind_source_dir_revalidate() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            let name = ServiceName::parse("pg").unwrap();
            let _ = s.create_service_dir(&name).unwrap();
            let token = s.validate_bind_source_dir("pg").unwrap();
            assert_eq!(token.object_kind(), BindObjectKind::Directory);
            assert_eq!(token.mode(), 0o700);
            assert_eq!(token.uid(), 0);
            token.revalidate().unwrap();
        }

        #[test]
        fn storage_validate_bind_source_file_revalidate() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.write_file_exclusive("f", b"data").unwrap();
            let token = s.validate_bind_source_file("f").unwrap();
            assert_eq!(token.object_kind(), BindObjectKind::File);
            assert_eq!(token.mode(), 0o600);
            assert_eq!(token.uid(), 0);
            token.revalidate().unwrap();
        }

        #[test]
        fn storage_bind_source_file_rejects_symlink() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            // Create a real file then symlink to it.
            s_write_file(&root, "real", b"data");
            std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
            let s = ServiceStorage::new(&root).unwrap();
            // validate_bind_source_file uses NOFOLLOW so a symlink basename
            // should be rejected (wrong type or openat2 failure).
            assert!(s.validate_bind_source_file("link").is_err());
        }

        #[test]
        fn storage_bind_source_file_rejects_wrong_mode() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            // Create a file with wrong mode (0644 instead of 0600).
            fs::write(root.join("f"), b"data").unwrap();
            let _ = fs::set_permissions(root.join("f"), fs::Permissions::from_mode(0o644));
            let s = ServiceStorage::new(&root).unwrap();
            assert!(s.validate_bind_source_file("f").is_err());
        }

        #[test]
        fn storage_bind_source_dir_rejects_wrong_mode() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            fs::create_dir_all(root.join("d")).unwrap();
            let _ = fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o755));
            let s = ServiceStorage::new(&root).unwrap();
            assert!(s.validate_bind_source_dir("d").is_err());
        }

        #[test]
        fn storage_rename_and_unlink() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.write_file_exclusive("tmp", b"data").unwrap();
            s.rename_descendant("tmp", "final").unwrap();
            let buf = s.read_file("final", 1024).unwrap();
            assert_eq!(buf, b"data");
            s.unlink_descendant("final").unwrap();
            assert!(s.read_file("final", 1024).is_err());
        }

        #[test]
        fn storage_unlink_descendant_dir() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.create_descendant_dir("emptygen").unwrap();
            s.unlink_descendant_dir("emptygen").unwrap();
            assert!(s.open_descendant_dir("emptygen").is_err());
        }

        #[test]
        fn storage_unlink_descendant_dir_rejects_nonempty() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.create_descendant_dir("gen").unwrap();
            s.write_file_exclusive("gen/file", b"x").unwrap();
            // Non-empty dir should fail.
            assert!(s.unlink_descendant_dir("gen").is_err());
        }

        #[test]
        fn storage_multi_component_mkdir_uses_parent_fd() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            // Create a nested dir: first parent, then child.
            s.create_descendant_dir("parent").unwrap();
            s.create_descendant_dir("parent/child").unwrap();
            // Verify it exists.
            let _fd = s.open_descendant_dir("parent/child").unwrap();
        }

        #[test]
        fn storage_fd_into_file_no_double_close() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.write_file_exclusive("f", b"x").unwrap();
            let (parent_fd, basename) = s.resolve_parent("f").unwrap();
            let cstr = CString::new(basename.as_bytes()).unwrap();
            let fd = openat2(
                &parent_fd,
                &cstr,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                DESCENDANT_RESOLVE_FLAGS,
            )
            .unwrap();
            let file = fd_into_file(fd).unwrap();
            let mut buf = Vec::new();
            use std::io::Read;
            file.try_clone().unwrap().read_to_end(&mut buf).unwrap();
            assert_eq!(buf, b"x");
            drop(file);
        }

        #[test]
        fn storage_read_size_cap() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.write_file_exclusive("f", &[b'a'; 200]).unwrap();
            assert!(s.read_file("f", 100).is_err());
        }

        #[test]
        fn storage_bind_source_revalidate_detects_inode_substitution() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            s.write_file_exclusive("f", b"data").unwrap();
            let token = s.validate_bind_source_file("f").unwrap();
            // Replace the file (unlink + recreate). The inode changes.
            s.unlink_descendant("f").unwrap();
            s.write_file_exclusive("f", b"new").unwrap();
            // Revalidate should detect the inode mismatch.
            assert!(token.revalidate().is_err());
        }

        /// Helper: write a file with 0600 mode using the storage layer.
        fn s_write_file(root: &Path, name: &str, data: &[u8]) {
            let s = ServiceStorage::new(root).unwrap();
            s.write_file_exclusive(name, data).unwrap();
        }

        #[test]
        fn storage_unlink_descendant_symlink() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            // Create a real file then symlink to it.
            s_write_file(&root, "real", b"data");
            std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
            let s = ServiceStorage::new(&root).unwrap();
            // unlink_descendant with empty() flags unlinks the symlink
            // itself (not the target).
            s.unlink_descendant("link").unwrap();
            // The symlink is gone, the target remains.
            assert!(s.read_file("link", 1024).is_err());
            assert!(s.read_file("real", 1024).is_ok());
        }

        #[test]
        fn storage_unlink_rejects_directory() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.create_descendant_dir("dir").unwrap();
            // unlink_descendant (file) should fail on a directory.
            assert!(s.unlink_descendant("dir").is_err());
            // Use unlink_descendant_dir for directories.
            s.unlink_descendant_dir("dir").unwrap();
            assert!(s.open_descendant_dir("dir").is_err());
        }

        // ─── pgdata child policy tests ───────────────────────────────

        #[test]
        fn pgdata_child_creates_0755_root_owned() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.create_descendant_dir("svc").unwrap();
            let token = s.create_pgdata_child("svc", "pgdata").unwrap();
            assert_eq!(token.uid(), 0);
            assert_eq!(token.mode(), 0o755);
            // The parent stays 0700.
            let parent_meta = fs::metadata(d.path().join("svc")).unwrap();
            assert_eq!(
                parent_meta.permissions().mode() & 0o7777,
                0o700,
                "parent data dir must stay 0700"
            );
            // The child is 0755.
            let child_meta = fs::metadata(d.path().join("svc/pgdata")).unwrap();
            assert_eq!(
                child_meta.permissions().mode() & 0o7777,
                0o755,
                "pgdata child must be 0755"
            );
        }

        #[test]
        fn pgdata_child_rejects_symlink() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            s.create_descendant_dir("svc").unwrap();
            // Create a symlink where pgdata should be.
            std::os::unix::fs::symlink("/etc", root.join("svc/pgdata")).unwrap();
            let result = s.create_pgdata_child("svc", "pgdata");
            assert!(
                result.is_err(),
                "symlink pgdata must be rejected, got {result:?}"
            );
        }

        #[test]
        fn pgdata_child_rejects_regular_file() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            s.create_descendant_dir("svc").unwrap();
            // Create a regular file where pgdata should be.
            fs::write(root.join("svc/pgdata"), b"not a dir").unwrap();
            let result = s.create_pgdata_child("svc", "pgdata");
            assert!(result.is_err(), "regular file pgdata must be rejected");
        }

        #[test]
        fn pgdata_child_rejects_wrong_mode_0777() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            s.create_descendant_dir("svc").unwrap();
            // Pre-create pgdata at 0777 (wrong mode).
            fs::create_dir(root.join("svc/pgdata")).unwrap();
            fs::set_permissions(root.join("svc/pgdata"), fs::Permissions::from_mode(0o777))
                .unwrap();
            let result = s.create_pgdata_child("svc", "pgdata");
            assert!(result.is_err(), "0777 pgdata must be rejected, not adopted");
        }

        #[test]
        fn pgdata_child_rejects_wrong_mode_0700() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            s.create_descendant_dir("svc").unwrap();
            // Pre-create pgdata at 0700 (wrong mode for pgdata).
            fs::create_dir(root.join("svc/pgdata")).unwrap();
            fs::set_permissions(root.join("svc/pgdata"), fs::Permissions::from_mode(0o700))
                .unwrap();
            let result = s.create_pgdata_child("svc", "pgdata");
            assert!(result.is_err(), "0700 pgdata must be rejected, not adopted");
        }

        #[test]
        fn pgdata_child_rejects_non_root_owner() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            s.create_descendant_dir("svc").unwrap();
            // Pre-create pgdata owned by UID 999 (non-root).
            fs::create_dir(root.join("svc/pgdata")).unwrap();
            fs::set_permissions(root.join("svc/pgdata"), fs::Permissions::from_mode(0o755))
                .unwrap();
            // Chown to non-root using rustix.
            use rustix::fs::{Gid, Uid, chown};
            let _ = chown(
                root.join("svc/pgdata"),
                Some(Uid::from_raw(999)),
                Some(Gid::from_raw(999)),
            );
            let result = s.create_pgdata_child("svc", "pgdata");
            assert!(result.is_err(), "non-root-owned pgdata must be rejected");
        }

        #[test]
        fn pgdata_child_revalidates_inode() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let s = ServiceStorage::new(d.path()).unwrap();
            s.create_descendant_dir("svc").unwrap();
            let token = s.create_pgdata_child("svc", "pgdata").unwrap();
            // Immediate revalidation should succeed (same inode).
            token.revalidate().expect("revalidate must succeed");
        }

        #[test]
        fn pgdata_child_no_mutation_on_blocked_root() {
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            // Create a service dir with a pre-existing foreign file at
            // pgdata position but NO marker; this should Block in the
            // provider, but here we test the storage layer: the foreign
            // file must not be modified.
            s.create_descendant_dir("svc").unwrap();
            fs::write(root.join("svc/pgdata"), b"foreign data").unwrap();
            let metadata_before = fs::metadata(root.join("svc/pgdata")).unwrap();
            let _ = s.create_pgdata_child("svc", "pgdata");
            // The file must not have been mutated.
            let metadata_after = fs::metadata(root.join("svc/pgdata")).unwrap();
            assert_eq!(
                metadata_before.len(),
                metadata_after.len(),
                "blocked pgdata must not be mutated"
            );
            assert!(
                fs::read(root.join("svc/pgdata"))
                    .unwrap()
                    .windows(12)
                    .any(|w| w == b"foreign data"),
                "blocked pgdata content must be unchanged"
            );
        }
        // ─── mount-boundary policy tests (root + CAP_SYS_ADMIN) ──────────

        /// RAII guard that unmounts a path on drop. Best-effort: if `umount`
        /// fails (e.g. busy), we log to stderr but do not panic.
        struct MountGuard {
            target: PathBuf,
            mounted: bool,
        }

        impl Drop for MountGuard {
            fn drop(&mut self) {
                if self.mounted {
                    let status = std::process::Command::new("umount")
                        .arg(&self.target)
                        .status();
                    if !matches!(status, Ok(s) if s.success()) {
                        eprintln!(
                            "MountGuard: umount {} failed (best-effort cleanup): {:?}",
                            self.target.display(),
                            status
                        );
                    }
                }
            }
        }

        /// Skip helper for mount tests: requires root and the `mount`
        /// command. Prints a clear skip reason.
        fn skip_if_no_mount_cap() -> bool {
            if rustix::process::getuid().as_raw() != 0 {
                eprintln!("skipping mount test: not running as root (requires CAP_SYS_ADMIN)");
                return true;
            }
            // Check that `mount` is available on PATH.
            if std::process::Command::new("mount")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_err()
            {
                eprintln!("skipping mount test: `mount` command not found on PATH");
                return true;
            }
            false
        }

        /// Mount a tmpfs at `target` and return a guard that unmounts on
        /// drop. Panics if mount fails.
        fn mount_tmpfs(target: &Path) -> MountGuard {
            let status = std::process::Command::new("mount")
                .args(["-t", "tmpfs", "tmpfs"])
                .arg(target)
                .status()
                .unwrap_or_else(|e| panic!("failed to execute mount: {e}"));
            assert!(
                status.success(),
                "mount -t tmpfs tmpfs {} failed (status: {:?}) — requires root + CAP_SYS_ADMIN",
                target.display(),
                status
            );
            MountGuard {
                target: target.to_path_buf(),
                mounted: true,
            }
        }

        /// Bind-mount `source` onto `target` and return a guard.
        fn mount_bind(source: &Path, target: &Path) -> MountGuard {
            let status = std::process::Command::new("mount")
                .args(["--bind"])
                .arg(source)
                .arg(target)
                .status()
                .unwrap_or_else(|e| panic!("failed to execute mount --bind: {e}"));
            assert!(
                status.success(),
                "mount --bind {} {} failed (status: {:?})",
                source.display(),
                target.display(),
                status
            );
            MountGuard {
                target: target.to_path_buf(),
                mounted: true,
            }
        }

        /// Verify that `path` is a mount point by comparing its `st_dev`
        /// with its parent's `st_dev`. If they differ, it's on a separate
        /// mount. (Note: on FCOS /var, st_dev can be the same even across a
        /// mount boundary, so this is a sufficient but not necessary check.)
        fn is_mount_point(path: &Path) -> bool {
            let st_self = rustix::fs::stat(path).ok();
            let st_parent = rustix::fs::stat(path.parent().unwrap_or(Path::new("/"))).ok();
            match (st_self, st_parent) {
                (Some(a), Some(b)) => a.st_dev != b.st_dev,
                _ => false,
            }
        }

        /// Verify that `path` is a mount point using `findmnt -M` which
        /// checks the kernel mount table (works even when st_dev is the
        /// same across a mount boundary, as on FCOS /var).
        fn is_mount_point_findmnt(path: &Path) -> bool {
            std::process::Command::new("findmnt")
                .args(["-M"])
                .arg(path)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }

        #[test]
        fn storage_constructor_allows_root_on_separate_volume() {
            if skip_if_no_mount_cap() {
                return;
            }
            // Create a parent tempdir, mount a tmpfs inside it, then create
            // the storage root on that tmpfs. The constructor must accept
            // the root even though it crosses a mount boundary from `/`.
            let parent = tempfile::tempdir().unwrap();
            let mountpoint = parent.path().join("mnt");
            fs::create_dir(&mountpoint).unwrap();
            let _guard = mount_tmpfs(&mountpoint);

            // Verify we actually crossed a mount boundary.
            assert!(
                is_mount_point_findmnt(&mountpoint) || is_mount_point(&mountpoint),
                "test fixture: {} must be a real mount point for this test to be meaningful",
                mountpoint.display()
            );

            // Create the storage root on the tmpfs, owned by root, mode 0700.
            let root = mountpoint.join("slip-root");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            // Ensure root ownership (tempdir may already be root, but be
            // explicit).
            use rustix::fs::{Gid, Uid, chown};
            let _ = chown(&root, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)));

            // The constructor must succeed despite the root being on a
            // separate mount from "/".
            let s = ServiceStorage::new(&root).unwrap_or_else(|e| {
                panic!(
                    "ServiceStorage::new must accept root on separate mount: {e} (root={})",
                    root.display()
                )
            });
            assert_eq!(s.root_path(), &root);
        }

        #[test]
        fn storage_rejects_mount_below_root() {
            if skip_if_no_mount_cap() {
                return;
            }
            // Construct storage on a valid root, create a child dir, mount
            // tmpfs on that child, then verify descendant access is rejected
            // with CrossDevice.
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            s.create_descendant_dir("child").unwrap();

            // Mount tmpfs on the child directory.
            let child_path = root.join("child");
            let _guard = mount_tmpfs(&child_path);

            // Verify it's a mount point.
            assert!(
                is_mount_point_findmnt(&child_path) || is_mount_point(&child_path),
                "test fixture: {} must be a real mount point",
                child_path.display()
            );

            // open_descendant_dir must reject with CrossDevice (NO_XDEV on
            // descendant operations).
            let result = s.open_descendant_dir("child");
            assert!(
                matches!(result, Err(StorageError::CrossDevice(_))),
                "descendant mount crossing must be rejected with CrossDevice, got: {result:?}"
            );

            // validate_bind_source_dir must also reject.
            let result = s.validate_bind_source_dir("child");
            assert!(
                matches!(result, Err(StorageError::CrossDevice(_))),
                "validate_bind_source_dir on mount-below-root must reject with CrossDevice, got: {result:?}"
            );
        }

        #[test]
        fn storage_rejects_same_superblock_bind_mount_below_root() {
            // Same-superblock bind mount: NO_XDEV must still reject even
            // when st_dev is the same on both sides (the FCOS /var case).
            if skip_if_no_mount_cap() {
                return;
            }
            let d = make_root();
            let root = d.path().to_path_buf();
            let s = ServiceStorage::new(&root).unwrap();
            s.create_descendant_dir("child").unwrap();

            // Create a source directory on the same filesystem, bind-mount
            // it onto the child.
            let src = root.join("bindsrc");
            fs::create_dir(&src).unwrap();
            let child_path = root.join("child");
            let _guard = mount_bind(&src, &child_path);

            // Even if st_dev is the same, NO_XDEV rejects the mount crossing.
            let result = s.open_descendant_dir("child");
            assert!(
                matches!(result, Err(StorageError::CrossDevice(_))),
                "same-superblock bind mount below root must be rejected by NO_XDEV, got: {result:?}"
            );
        }

        #[test]
        fn storage_constructor_rejects_ancestor_symlink() {
            // Root acquisition with ROOT_RESOLVE_FLAGS must still reject
            // symlinks (NO_SYMLINKS is retained). An ancestor symlink in
            // the configured path must be rejected.
            if skip_if_nonroot() {
                return;
            }
            let d = make_root();
            let real = d.path().join("real_root");
            fs::create_dir(&real).unwrap();
            fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
            // Create a symlink pointing to real_root as the "configured" root.
            let link = d.path().join("rootlink");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            // ServiceStorage::new must reject because the final component
            // is a symlink (NO_SYMLINKS rejects symlinks in resolution).
            let result = ServiceStorage::new(&link);
            assert!(
                result.is_err(),
                "constructor must reject symlink as configured root, got: {result:?}"
            );
        }

        #[test]
        fn storage_constructor_rejects_intermediate_symlink_in_path() {
            // An intermediate symlink in the ancestor path must be rejected
            // by NO_SYMLINKS even with ROOT_RESOLVE_FLAGS.
            if skip_if_nonroot() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            // Create real_root as a valid 0700 root-owned directory.
            let real_root = d.path().join("real_root");
            fs::create_dir(&real_root).unwrap();
            fs::set_permissions(&real_root, fs::Permissions::from_mode(0o700)).unwrap();
            // Create a symlink "linkdir" -> "real_root".
            std::os::unix::fs::symlink(&real_root, d.path().join("linkdir")).unwrap();
            // The configured path goes through the symlink.
            let configured = d.path().join("linkdir");
            let result = ServiceStorage::new(&configured);
            assert!(
                result.is_err(),
                "constructor must reject intermediate symlink in root path, got: {result:?}"
            );
        }

        #[test]
        fn storage_constructor_rejects_wrong_uid_root() {
            if skip_if_nonroot() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let root = d.path().join("wronguid");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            // Chown to non-root.
            use rustix::fs::{Gid, Uid, chown};
            let _ = chown(&root, Some(Uid::from_raw(999)), Some(Gid::from_raw(999)));
            let result = ServiceStorage::new(&root);
            assert!(
                matches!(result, Err(StorageError::WrongOwner { .. })),
                "constructor must reject non-root-owned root, got: {result:?}"
            );
        }

        #[test]
        fn storage_constructor_rejects_wrong_mode_root() {
            if skip_if_nonroot() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let root = d.path().join("wrongmode");
            fs::create_dir(&root).unwrap();
            // Wrong mode (0755 instead of 0700).
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            let result = ServiceStorage::new(&root);
            assert!(
                matches!(result, Err(StorageError::WrongMode { .. })),
                "constructor must reject wrong-mode root, got: {result:?}"
            );
        }

        #[test]
        fn storage_constructor_rejects_non_directory_root() {
            if skip_if_nonroot() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let root = d.path().join("notafile");
            fs::write(&root, b"not a directory").unwrap();
            let result = ServiceStorage::new(&root);
            assert!(
                result.is_err(),
                "constructor must reject non-directory root, got: {result:?}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub use _linux::{ServiceStorage, ValidatedBindSource};
