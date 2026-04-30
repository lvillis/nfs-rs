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
    AUTH_NONE, AUTH_SYS, AccessResult, AppDataBlock, BackchannelCtlArgs, BasicAttributes,
    BindConnToSessionArgs, BindConnToSessionResult, Bitmap, CREATE_SESSION4_FLAG_CONN_BACK_CHAN,
    CREATE_SESSION4_FLAG_CONN_RDMA, CREATE_SESSION4_FLAG_PERSIST, CallbackClient, CallbackSecParms,
    ChangeAttrType, ChannelDirFromClient, ChannelDirFromServer, CloneArgs, CommitResult, CopyArgs,
    CopyNotifyArgs, CopyNotifyResult, CopyRequirements, CopyResult, CreateMode, DelegationClaim,
    DeviceAddr, DeviceError, DeviceId, EXCHGID4_FLAG_BIND_PRINC_STATEID, EXCHGID4_FLAG_CONFIRMED_R,
    EXCHGID4_FLAG_MASK_PNFS, EXCHGID4_FLAG_SUPP_MOVED_MIGR, EXCHGID4_FLAG_SUPP_MOVED_REFER,
    EXCHGID4_FLAG_UPD_CONFIRMED_REC_A, EXCHGID4_FLAG_USE_NON_PNFS, EXCHGID4_FLAG_USE_PNFS_DS,
    EXCHGID4_FLAG_USE_PNFS_MDS, FATTR4_ACL, FATTR4_ACLSUPPORT, FATTR4_ARCHIVE, FATTR4_CANSETTIME,
    FATTR4_CASE_INSENSITIVE, FATTR4_CASE_PRESERVING, FATTR4_CHANGE, FATTR4_CHANGE_ATTR_TYPE,
    FATTR4_CHANGE_POLICY, FATTR4_CHOWN_RESTRICTED, FATTR4_CLONE_BLKSIZE, FATTR4_DACL,
    FATTR4_DIR_NOTIF_DELAY, FATTR4_DIRENT_NOTIF_DELAY, FATTR4_FH_EXPIRE_TYPE, FATTR4_FILEHANDLE,
    FATTR4_FILEID, FATTR4_FILES_AVAIL, FATTR4_FILES_FREE, FATTR4_FILES_TOTAL,
    FATTR4_FS_CHARSET_CAP, FATTR4_FS_LAYOUT_TYPE, FATTR4_FS_LOCATIONS, FATTR4_FS_LOCATIONS_INFO,
    FATTR4_FS_STATUS, FATTR4_FSID, FATTR4_HIDDEN, FATTR4_HOMOGENEOUS, FATTR4_LAYOUT_ALIGNMENT,
    FATTR4_LAYOUT_BLKSIZE, FATTR4_LAYOUT_HINT, FATTR4_LAYOUT_TYPE, FATTR4_LEASE_TIME,
    FATTR4_LINK_SUPPORT, FATTR4_MAXFILESIZE, FATTR4_MAXLINK, FATTR4_MAXNAME, FATTR4_MAXREAD,
    FATTR4_MAXWRITE, FATTR4_MDSTHRESHOLD, FATTR4_MIMETYPE, FATTR4_MODE, FATTR4_MODE_SET_MASKED,
    FATTR4_MOUNTED_ON_FILEID, FATTR4_NAMED_ATTR, FATTR4_NO_TRUNC, FATTR4_NUMLINKS, FATTR4_OWNER,
    FATTR4_OWNER_GROUP, FATTR4_QUOTA_AVAIL_HARD, FATTR4_QUOTA_AVAIL_SOFT, FATTR4_QUOTA_USED,
    FATTR4_RAWDEV, FATTR4_RDATTR_ERROR, FATTR4_RETENTEVT_GET, FATTR4_RETENTEVT_SET,
    FATTR4_RETENTION_GET, FATTR4_RETENTION_HOLD, FATTR4_RETENTION_SET, FATTR4_SACL,
    FATTR4_SEC_LABEL, FATTR4_SIZE, FATTR4_SPACE_AVAIL, FATTR4_SPACE_FREE, FATTR4_SPACE_FREED,
    FATTR4_SPACE_TOTAL, FATTR4_SPACE_USED, FATTR4_SUPPATTR_EXCLCREAT, FATTR4_SUPPORTED_ATTRS,
    FATTR4_SYMLINK_SUPPORT, FATTR4_SYSTEM, FATTR4_TIME_ACCESS, FATTR4_TIME_ACCESS_SET,
    FATTR4_TIME_BACKUP, FATTR4_TIME_CREATE, FATTR4_TIME_DELTA, FATTR4_TIME_METADATA,
    FATTR4_TIME_MODIFY, FATTR4_TIME_MODIFY_SET, FATTR4_UNIQUE_HANDLES, FileType, FsInfo, FsStat,
    GDD4_OK, GDD4_UNAVAIL, GetDeviceInfoArgs, GetDeviceInfoResult, GetDeviceListArgs,
    GetDeviceListResult, GetDirDelegationArgs, GetDirDelegationResult, IoAdviceType, IoAdviseArgs,
    IoAdviseResult, IoInfo, LAYOUT4_BLOCK_VOLUME, LAYOUT4_NFSV4_1_FILES, LAYOUT4_OSD2_OBJECTS,
    LAYOUTIOMODE4_ANY, LAYOUTIOMODE4_READ, LAYOUTIOMODE4_RW, LAYOUTRETURN4_ALL, LAYOUTRETURN4_FILE,
    LAYOUTRETURN4_FSID, Layout, LayoutCommitArgs, LayoutCommitResult, LayoutContent,
    LayoutErrorArgs, LayoutGetArgs, LayoutGetResult, LayoutIomode, LayoutReturn, LayoutReturnArgs,
    LayoutReturnFile, LayoutReturnResult, LayoutStatsArgs, LayoutType, LayoutUpdate, LockArgs,
    LockDenied, LockOwner, LockTestArgs, LockType, LockUnlockArgs, Locker, NFS4_CONTENT_DATA,
    NFS4_CONTENT_HOLE, NFS4_DEVICEID_SIZE, NFS4_FHSIZE, NFS4_INT32_MAX, NFS4_INT64_MAX,
    NFS4_MAX_CALLBACK_SEC_PARMS, NFS4_MAX_DEVICEIDS, NFS4_MAX_LAYOUT_ERRORS, NFS4_MAX_LAYOUTS,
    NFS4_MAX_NETLOCATIONS, NFS4_MAX_READ_PLUS_SEGMENTS, NFS4_MAX_SECINFO_FLAVORS, NFS4_MAXFILELEN,
    NFS4_MAXFILEOFF, NFS4_MINOR_VERSION_LATEST, NFS4_OPAQUE_LIMIT, NFS4_PORT, NFS4_SESSIONID_SIZE,
    NFS4_UINT32_MAX, NFS4_UINT64_MAX, NFS4_VERIFIER_SIZE, NetAddr, NetLoc, NfsAce, NfsSpaceLimit,
    NfsTime, OPEN4_RESULT_CONFIRM, OPEN4_RESULT_LOCKTYPE_POSIX, OPEN4_RESULT_MAY_NOTIFY_LOCK,
    OPEN4_RESULT_PRESERVE_UNLINKED, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_ACCESS_READ,
    OPEN4_SHARE_ACCESS_WANT_ANY_DELEG, OPEN4_SHARE_ACCESS_WANT_CANCEL,
    OPEN4_SHARE_ACCESS_WANT_DELEG_MASK, OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
    OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE, OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED,
    OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL,
    OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG, OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_BOTH,
    OPEN4_SHARE_DENY_NONE, OPEN4_SHARE_DENY_READ, OPEN4_SHARE_DENY_WRITE, OffloadStatusResult,
    OpenClaimType, OpenDelegation, OpenDelegationType, OpenNoneDelegation, OpenReadDelegation,
    OpenType, OpenWriteDelegation, PathConf, RPC_GSS_SVC_INTEGRITY, RPC_GSS_SVC_NONE,
    RPC_GSS_SVC_PRIVACY, RPCSEC_GSS, ReadPlusArgs, ReadPlusContent, ReadPlusResult, RpcGssService,
    SEQ4_STATUS_ADMIN_STATE_REVOKED, SEQ4_STATUS_BACKCHANNEL_FAULT,
    SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED, SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING,
    SEQ4_STATUS_CB_PATH_DOWN, SEQ4_STATUS_CB_PATH_DOWN_SESSION, SEQ4_STATUS_DEVID_CHANGED,
    SEQ4_STATUS_DEVID_DELETED, SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED,
    SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED, SEQ4_STATUS_LEASE_MOVED,
    SEQ4_STATUS_RECALLABLE_STATE_REVOKED, SEQ4_STATUS_RESTART_RECLAIM_NEEDED, SecInfo,
    SecInfoStyle, SeekContent, SeekResult, SetAttrs, SetClientIdArgs, SetClientIdConfirmArgs,
    SetClientIdResult, SetSsvArgs, SetSsvResult, SetTime, StableHow, StateProtectHow, Status,
    Verifier, WantDelegationArgs, WhyNoDelegation, WriteResponse, WriteSameArgs,
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
