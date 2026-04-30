//! NFSv4.2 client support.
//!
//! NFSv4 is session-based and uses the server's v4 pseudo-filesystem rather
//! than the NFSv3 MOUNT service. Paths passed to this module are absolute paths
//! in that pseudo-filesystem, for example `/export/file.txt`.
//!
//! Use [`blocking::Client`] with the default `blocking` feature, or
//! [`tokio::Client`] with the `tokio` feature.

#![cfg_attr(not(any(feature = "blocking", feature = "tokio")), allow(dead_code))]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

#[cfg(feature = "blocking")]
pub mod blocking;
mod client;
mod proto;

#[cfg(feature = "tokio")]
pub mod tokio;

/// Low-level NFSv4 wire types and COMPOUND operation structures.
///
/// This module is available with the `protocol` feature. It exposes the
/// protocol representation used by the clients, but the stable application API
/// is the path-oriented client layer.
#[cfg(feature = "protocol")]
pub mod protocol {
    pub use super::proto::*;
}

pub use client::{DirEntry, DirPage, DirPageCursor};
pub use proto::{
    ACCESS4_DELETE, ACCESS4_EXECUTE, ACCESS4_EXTEND, ACCESS4_LOOKUP, ACCESS4_MODIFY, ACCESS4_READ,
    AccessResult, BasicAttributes, Bitmap, CommitResult, FATTR4_CANSETTIME,
    FATTR4_CASE_INSENSITIVE, FATTR4_CASE_PRESERVING, FATTR4_CHANGE, FATTR4_CHOWN_RESTRICTED,
    FATTR4_FH_EXPIRE_TYPE, FATTR4_FILEID, FATTR4_FILES_AVAIL, FATTR4_FILES_FREE,
    FATTR4_FILES_TOTAL, FATTR4_HOMOGENEOUS, FATTR4_LINK_SUPPORT, FATTR4_MAXFILESIZE,
    FATTR4_MAXLINK, FATTR4_MAXNAME, FATTR4_MAXREAD, FATTR4_MAXWRITE, FATTR4_MODE, FATTR4_NO_TRUNC,
    FATTR4_NUMLINKS, FATTR4_OWNER, FATTR4_OWNER_GROUP, FATTR4_SIZE, FATTR4_SPACE_AVAIL,
    FATTR4_SPACE_FREE, FATTR4_SPACE_TOTAL, FATTR4_SPACE_USED, FATTR4_SUPPORTED_ATTRS,
    FATTR4_SYMLINK_SUPPORT, FATTR4_TIME_ACCESS, FATTR4_TIME_ACCESS_SET, FATTR4_TIME_DELTA,
    FATTR4_TIME_METADATA, FATTR4_TIME_MODIFY, FATTR4_TIME_MODIFY_SET, FileType, FsInfo, FsStat,
    NFS4_FHSIZE, NFS4_MINOR_VERSION_LATEST, NFS4_OPAQUE_LIMIT, NFS4_PORT, NFS4_SESSIONID_SIZE,
    NFS4_VERIFIER_SIZE, NfsTime, PathConf, SeekContent, SeekResult, SetAttrs, SetTime, StableHow,
    Status, Verifier,
};

pub(crate) fn validate_owner_id(owner_id: &[u8]) -> Result<()> {
    validate_opaque_id("owner_id", owner_id)
}

pub(crate) fn validate_open_owner(open_owner: &[u8]) -> Result<()> {
    validate_opaque_id("open_owner", open_owner)
}

fn validate_opaque_id(name: &'static str, value: &[u8]) -> Result<()> {
    if value.len() > proto::NFS4_OPAQUE_LIMIT {
        return Err(Error::Protocol(format!(
            "NFSv4 {name} length {} exceeds opaque limit {}",
            value.len(),
            proto::NFS4_OPAQUE_LIMIT
        )));
    }
    Ok(())
}

pub(crate) fn validate_transfer_size(name: &'static str, size: u32) -> Result<()> {
    if size == 0 || size as usize > proto::NFS4_MAX_IO {
        return Err(Error::Protocol(format!(
            "{name} must be in 1..={} bytes",
            proto::NFS4_MAX_IO
        )));
    }
    Ok(())
}

pub(crate) fn validate_max_dir_entries(max_dir_entries: usize) -> Result<()> {
    if max_dir_entries == 0 {
        return Err(Error::Protocol(
            "max_dir_entries must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn clamp_io_size(server_max: Option<u64>, configured_limit: u32) -> u32 {
    match server_max {
        Some(0) | None => configured_limit,
        Some(max) => u64::from(configured_limit).min(max).max(1) as u32,
    }
}

pub(crate) fn default_owner_id(host: &str) -> Vec<u8> {
    default_opaque_id("client", host)
}

pub(crate) fn default_open_owner(host: &str) -> Vec<u8> {
    default_opaque_id("open", host)
}

fn default_opaque_id(kind: &str, host: &str) -> Vec<u8> {
    static NEXT_OWNER_ID: AtomicU64 = AtomicU64::new(1);

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "nfs-rs:{kind}:{:016x}:{}:{}:{}",
        fnv1a64(host.as_bytes()),
        std::process::id(),
        duration.as_nanos(),
        NEXT_OWNER_ID.fetch_add(1, Ordering::Relaxed)
    )
    .into_bytes()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    bytes.iter().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_owner_id_is_unique_and_bounded() {
        let first = default_owner_id(&"host".repeat(2_000));
        let second = default_owner_id(&"host".repeat(2_000));

        assert_ne!(first, second);
        assert!(first.len() <= NFS4_OPAQUE_LIMIT);
        assert!(second.len() <= NFS4_OPAQUE_LIMIT);
    }

    #[test]
    fn validate_owner_id_rejects_oversized_values() {
        let owner_id = vec![0; NFS4_OPAQUE_LIMIT + 1];
        assert!(matches!(
            validate_owner_id(&owner_id),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validate_open_owner_rejects_oversized_values() {
        let open_owner = vec![0; NFS4_OPAQUE_LIMIT + 1];
        assert!(matches!(
            validate_open_owner(&open_owner),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn validate_transfer_size_rejects_invalid_values() {
        assert!(matches!(
            validate_transfer_size("read_size", 0),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            validate_transfer_size("read_size", proto::NFS4_MAX_IO as u32 + 1),
            Err(Error::Protocol(_))
        ));
        assert!(validate_transfer_size("read_size", proto::NFS4_MAX_IO as u32).is_ok());
    }

    #[test]
    fn clamps_io_size_to_server_advertised_limits() {
        assert_eq!(clamp_io_size(None, 128 * 1024), 128 * 1024);
        assert_eq!(clamp_io_size(Some(0), 128 * 1024), 128 * 1024);
        assert_eq!(clamp_io_size(Some(64 * 1024), 128 * 1024), 64 * 1024);
        assert_eq!(clamp_io_size(Some(1024 * 1024), 128 * 1024), 128 * 1024);
    }

    #[test]
    fn validate_max_dir_entries_rejects_zero() {
        assert!(matches!(
            validate_max_dir_entries(0),
            Err(Error::Protocol(_))
        ));
        assert!(validate_max_dir_entries(1).is_ok());
    }
}
