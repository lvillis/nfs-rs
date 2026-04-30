#![cfg_attr(not(feature = "protocol"), allow(dead_code))]

use crate::error::{Error, Result};
use crate::xdr::{Decode, Decoder, Encode, Encoder};

pub const NFS4_PROGRAM: u32 = 100003;
pub const NFS4_VERSION: u32 = 4;
pub const NFS4_PORT: u16 = 2049;
pub const NFS4_MINOR_VERSION_LATEST: u32 = 2;

pub const NFS4_FHSIZE: usize = 128;
pub const NFS4_VERIFIER_SIZE: usize = 8;
pub const NFS4_OPAQUE_LIMIT: usize = 1024;
pub const NFS4_SESSIONID_SIZE: usize = 16;
pub const NFS4_MAX_OPS: usize = 128;
pub const NFS4_MAX_IO: usize = 64 * 1024 * 1024;
pub const NFS4_MAX_DIR_ENTRIES: usize = 1_000_000;

pub const FATTR4_SUPPORTED_ATTRS: u32 = 0;
pub const FATTR4_TYPE: u32 = 1;
pub const FATTR4_FH_EXPIRE_TYPE: u32 = 2;
pub const FATTR4_CHANGE: u32 = 3;
pub const FATTR4_SIZE: u32 = 4;
pub const FATTR4_LINK_SUPPORT: u32 = 5;
pub const FATTR4_SYMLINK_SUPPORT: u32 = 6;
pub const FATTR4_UNIQUE_HANDLES: u32 = 9;
pub const FATTR4_LEASE_TIME: u32 = 10;
pub const FATTR4_CANSETTIME: u32 = 15;
pub const FATTR4_CASE_INSENSITIVE: u32 = 16;
pub const FATTR4_CASE_PRESERVING: u32 = 17;
pub const FATTR4_CHOWN_RESTRICTED: u32 = 18;
pub const FATTR4_FILEID: u32 = 20;
pub const FATTR4_FILES_AVAIL: u32 = 21;
pub const FATTR4_FILES_FREE: u32 = 22;
pub const FATTR4_FILES_TOTAL: u32 = 23;
pub const FATTR4_HOMOGENEOUS: u32 = 26;
pub const FATTR4_MAXFILESIZE: u32 = 27;
pub const FATTR4_MAXLINK: u32 = 28;
pub const FATTR4_MAXNAME: u32 = 29;
pub const FATTR4_MAXREAD: u32 = 30;
pub const FATTR4_MAXWRITE: u32 = 31;
pub const FATTR4_MODE: u32 = 33;
pub const FATTR4_NO_TRUNC: u32 = 34;
pub const FATTR4_NUMLINKS: u32 = 35;
pub const FATTR4_OWNER: u32 = 36;
pub const FATTR4_OWNER_GROUP: u32 = 37;
pub const FATTR4_SPACE_AVAIL: u32 = 42;
pub const FATTR4_SPACE_FREE: u32 = 43;
pub const FATTR4_SPACE_TOTAL: u32 = 44;
pub const FATTR4_SPACE_USED: u32 = 45;
pub const FATTR4_TIME_ACCESS: u32 = 47;
pub const FATTR4_TIME_ACCESS_SET: u32 = 48;
pub const FATTR4_TIME_DELTA: u32 = 51;
pub const FATTR4_TIME_METADATA: u32 = 52;
pub const FATTR4_TIME_MODIFY: u32 = 53;
pub const FATTR4_TIME_MODIFY_SET: u32 = 54;
pub const FATTR4_BASIC_ATTRS: &[u32] = &[
    FATTR4_TYPE,
    FATTR4_CHANGE,
    FATTR4_SIZE,
    FATTR4_FILEID,
    FATTR4_MODE,
    FATTR4_NUMLINKS,
    FATTR4_OWNER,
    FATTR4_OWNER_GROUP,
    FATTR4_SPACE_USED,
    FATTR4_TIME_ACCESS,
    FATTR4_TIME_METADATA,
    FATTR4_TIME_MODIFY,
];
pub const FATTR4_FSSTAT_ATTRS: &[u32] = &[
    FATTR4_FILES_AVAIL,
    FATTR4_FILES_FREE,
    FATTR4_FILES_TOTAL,
    FATTR4_SPACE_AVAIL,
    FATTR4_SPACE_FREE,
    FATTR4_SPACE_TOTAL,
];
pub const FATTR4_FSINFO_ATTRS: &[u32] = &[
    FATTR4_FH_EXPIRE_TYPE,
    FATTR4_LINK_SUPPORT,
    FATTR4_SYMLINK_SUPPORT,
    FATTR4_UNIQUE_HANDLES,
    FATTR4_LEASE_TIME,
    FATTR4_CANSETTIME,
    FATTR4_HOMOGENEOUS,
    FATTR4_MAXFILESIZE,
    FATTR4_MAXREAD,
    FATTR4_MAXWRITE,
    FATTR4_TIME_DELTA,
];
pub const FATTR4_PATHCONF_ATTRS: &[u32] = &[
    FATTR4_CASE_INSENSITIVE,
    FATTR4_CASE_PRESERVING,
    FATTR4_CHOWN_RESTRICTED,
    FATTR4_MAXLINK,
    FATTR4_MAXNAME,
    FATTR4_NO_TRUNC,
];
pub const NF4REG: u32 = 1;
pub const NF4DIR: u32 = 2;
pub const NF4BLK: u32 = 3;
pub const NF4CHR: u32 = 4;
pub const NF4LNK: u32 = 5;
pub const NF4SOCK: u32 = 6;
pub const NF4FIFO: u32 = 7;
pub const OPEN4_SHARE_ACCESS_READ: u32 = 0x0000_0001;
pub const OPEN4_SHARE_ACCESS_WRITE: u32 = 0x0000_0002;
pub const OPEN4_SHARE_ACCESS_BOTH: u32 = 0x0000_0003;
pub const OPEN4_SHARE_ACCESS_WANT_NO_DELEG: u32 = 0x0000_0400;
pub const OPEN4_SHARE_DENY_NONE: u32 = 0x0000_0000;
pub const ACCESS4_READ: u32 = 0x0001;
pub const ACCESS4_LOOKUP: u32 = 0x0002;
pub const ACCESS4_MODIFY: u32 = 0x0004;
pub const ACCESS4_EXTEND: u32 = 0x0008;
pub const ACCESS4_DELETE: u32 = 0x0010;
pub const ACCESS4_EXECUTE: u32 = 0x0020;

/// NFSv4 verifier value.
pub type Verifier = [u8; NFS4_VERIFIER_SIZE];
/// NFSv4 session id.
pub type SessionId = [u8; NFS4_SESSIONID_SIZE];

/// NFSv4 status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Perm,
    NoEnt,
    Io,
    Nxio,
    Access,
    Exist,
    Xdev,
    NotDir,
    IsDir,
    Inval,
    Fbig,
    NoSpc,
    ReadOnlyFs,
    Mlink,
    NameTooLong,
    NotEmpty,
    Dquot,
    Stale,
    Expired,
    BadHandle,
    BadCookie,
    NotSupported,
    TooSmall,
    ServerFault,
    BadType,
    Delay,
    StaleClientId,
    StaleStateId,
    OldStateId,
    BadStateId,
    LeaseMoved,
    WrongSec,
    NoFileHandle,
    MinorVersionMismatch,
    BadSession,
    AdminRevoked,
    SeqMisordered,
    OpNotInSession,
    DeadSession,
    WrongType,
    UnionNotSupported,
    Unknown(u32),
}

impl Status {
    /// Converts a raw NFSv4 status code into [`Status`].
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::Perm,
            2 => Self::NoEnt,
            5 => Self::Io,
            6 => Self::Nxio,
            13 => Self::Access,
            17 => Self::Exist,
            18 => Self::Xdev,
            20 => Self::NotDir,
            21 => Self::IsDir,
            22 => Self::Inval,
            27 => Self::Fbig,
            28 => Self::NoSpc,
            30 => Self::ReadOnlyFs,
            31 => Self::Mlink,
            63 => Self::NameTooLong,
            66 => Self::NotEmpty,
            69 => Self::Dquot,
            70 => Self::Stale,
            10011 => Self::Expired,
            10001 => Self::BadHandle,
            10003 => Self::BadCookie,
            10004 => Self::NotSupported,
            10005 => Self::TooSmall,
            10006 => Self::ServerFault,
            10007 => Self::BadType,
            10008 => Self::Delay,
            10022 => Self::StaleClientId,
            10023 => Self::StaleStateId,
            10024 => Self::OldStateId,
            10025 => Self::BadStateId,
            10031 => Self::LeaseMoved,
            10016 => Self::WrongSec,
            10020 => Self::NoFileHandle,
            10021 => Self::MinorVersionMismatch,
            10052 => Self::BadSession,
            10047 => Self::AdminRevoked,
            10063 => Self::SeqMisordered,
            10071 => Self::OpNotInSession,
            10078 => Self::DeadSession,
            10083 => Self::WrongType,
            10090 => Self::UnionNotSupported,
            value => Self::Unknown(value),
        }
    }

    /// Returns the raw NFSv4 status code.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::Perm => 1,
            Self::NoEnt => 2,
            Self::Io => 5,
            Self::Nxio => 6,
            Self::Access => 13,
            Self::Exist => 17,
            Self::Xdev => 18,
            Self::NotDir => 20,
            Self::IsDir => 21,
            Self::Inval => 22,
            Self::Fbig => 27,
            Self::NoSpc => 28,
            Self::ReadOnlyFs => 30,
            Self::Mlink => 31,
            Self::NameTooLong => 63,
            Self::NotEmpty => 66,
            Self::Dquot => 69,
            Self::Stale => 70,
            Self::Expired => 10011,
            Self::BadHandle => 10001,
            Self::BadCookie => 10003,
            Self::NotSupported => 10004,
            Self::TooSmall => 10005,
            Self::ServerFault => 10006,
            Self::BadType => 10007,
            Self::Delay => 10008,
            Self::StaleClientId => 10022,
            Self::StaleStateId => 10023,
            Self::OldStateId => 10024,
            Self::BadStateId => 10025,
            Self::LeaseMoved => 10031,
            Self::WrongSec => 10016,
            Self::NoFileHandle => 10020,
            Self::MinorVersionMismatch => 10021,
            Self::BadSession => 10052,
            Self::AdminRevoked => 10047,
            Self::SeqMisordered => 10063,
            Self::OpNotInSession => 10071,
            Self::DeadSession => 10078,
            Self::WrongType => 10083,
            Self::UnionNotSupported => 10090,
            Self::Unknown(value) => value,
        }
    }

    /// Returns true for `NFS4_OK`.
    pub fn is_ok(self) -> bool {
        self == Self::Ok
    }

    /// Returns true when the client should create a new session and retry.
    pub fn requires_session_recovery(self) -> bool {
        matches!(
            self,
            Self::BadSession | Self::DeadSession | Self::StaleClientId
        )
    }

    /// Returns true when the status indicates lost NFSv4 state.
    pub fn indicates_lost_state(self) -> bool {
        matches!(
            self,
            Self::AdminRevoked
                | Self::BadStateId
                | Self::Expired
                | Self::LeaseMoved
                | Self::OldStateId
                | Self::StaleClientId
                | Self::StaleStateId
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum OpCode {
    Access = 3,
    Close = 4,
    Commit = 5,
    Create = 6,
    GetAttr = 9,
    GetFh = 10,
    Link = 11,
    Lookup = 15,
    Lookupp = 16,
    Open = 18,
    PutFh = 22,
    PutPubFh = 23,
    PutRootFh = 24,
    Read = 25,
    ReadDir = 26,
    ReadLink = 27,
    Remove = 28,
    Rename = 29,
    RestoreFh = 31,
    SaveFh = 32,
    SetAttr = 34,
    Write = 38,
    ExchangeId = 42,
    CreateSession = 43,
    DestroySession = 44,
    FreeStateId = 45,
    SecInfoNoName = 52,
    Sequence = 53,
    ReclaimComplete = 58,
    Allocate = 59,
    Copy = 60,
    CopyNotify = 61,
    Deallocate = 62,
    IoAdvise = 63,
    LayoutError = 64,
    LayoutStats = 65,
    OffloadCancel = 66,
    OffloadStatus = 67,
    ReadPlus = 68,
    Seek = 69,
    WriteSame = 70,
    Clone = 71,
    Illegal = 10044,
}

impl OpCode {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            3 => Self::Access,
            4 => Self::Close,
            5 => Self::Commit,
            6 => Self::Create,
            9 => Self::GetAttr,
            10 => Self::GetFh,
            11 => Self::Link,
            15 => Self::Lookup,
            16 => Self::Lookupp,
            18 => Self::Open,
            22 => Self::PutFh,
            23 => Self::PutPubFh,
            24 => Self::PutRootFh,
            25 => Self::Read,
            26 => Self::ReadDir,
            27 => Self::ReadLink,
            28 => Self::Remove,
            29 => Self::Rename,
            31 => Self::RestoreFh,
            32 => Self::SaveFh,
            34 => Self::SetAttr,
            38 => Self::Write,
            42 => Self::ExchangeId,
            43 => Self::CreateSession,
            44 => Self::DestroySession,
            45 => Self::FreeStateId,
            52 => Self::SecInfoNoName,
            53 => Self::Sequence,
            58 => Self::ReclaimComplete,
            59 => Self::Allocate,
            60 => Self::Copy,
            61 => Self::CopyNotify,
            62 => Self::Deallocate,
            63 => Self::IoAdvise,
            64 => Self::LayoutError,
            65 => Self::LayoutStats,
            66 => Self::OffloadCancel,
            67 => Self::OffloadStatus,
            68 => Self::ReadPlus,
            69 => Self::Seek,
            70 => Self::WriteSame,
            71 => Self::Clone,
            10044 => Self::Illegal,
            _ => return None,
        })
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Access => "ACCESS",
            Self::Close => "CLOSE",
            Self::Commit => "COMMIT",
            Self::Create => "CREATE",
            Self::GetAttr => "GETATTR",
            Self::GetFh => "GETFH",
            Self::Link => "LINK",
            Self::Lookup => "LOOKUP",
            Self::Lookupp => "LOOKUPP",
            Self::Open => "OPEN",
            Self::PutFh => "PUTFH",
            Self::PutPubFh => "PUTPUBFH",
            Self::PutRootFh => "PUTROOTFH",
            Self::Read => "READ",
            Self::ReadDir => "READDIR",
            Self::ReadLink => "READLINK",
            Self::Remove => "REMOVE",
            Self::Rename => "RENAME",
            Self::RestoreFh => "RESTOREFH",
            Self::SaveFh => "SAVEFH",
            Self::SetAttr => "SETATTR",
            Self::Write => "WRITE",
            Self::ExchangeId => "EXCHANGE_ID",
            Self::CreateSession => "CREATE_SESSION",
            Self::DestroySession => "DESTROY_SESSION",
            Self::FreeStateId => "FREE_STATEID",
            Self::SecInfoNoName => "SECINFO_NO_NAME",
            Self::Sequence => "SEQUENCE",
            Self::ReclaimComplete => "RECLAIM_COMPLETE",
            Self::Allocate => "ALLOCATE",
            Self::Copy => "COPY",
            Self::CopyNotify => "COPY_NOTIFY",
            Self::Deallocate => "DEALLOCATE",
            Self::IoAdvise => "IO_ADVISE",
            Self::LayoutError => "LAYOUTERROR",
            Self::LayoutStats => "LAYOUTSTATS",
            Self::OffloadCancel => "OFFLOAD_CANCEL",
            Self::OffloadStatus => "OFFLOAD_STATUS",
            Self::ReadPlus => "READ_PLUS",
            Self::Seek => "SEEK",
            Self::WriteSame => "WRITE_SAME",
            Self::Clone => "CLONE",
            Self::Illegal => "ILLEGAL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileHandle {
    data: Vec<u8>,
}

impl FileHandle {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        if data.len() > NFS4_FHSIZE {
            return Err(Error::Protocol(format!(
                "NFSv4 file handle is {} bytes, maximum is {NFS4_FHSIZE}",
                data.len()
            )));
        }
        Ok(Self { data })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Encode for FileHandle {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_opaque(&self.data, NFS4_FHSIZE)
    }
}

impl Decode for FileHandle {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            data: decoder.read_opaque_vec(NFS4_FHSIZE)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateId {
    pub seqid: u32,
    pub other: [u8; 12],
}

impl StateId {
    pub fn anonymous() -> Self {
        Self {
            seqid: 0,
            other: [0; 12],
        }
    }
}

impl Encode for StateId {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.seqid);
        encoder.write_fixed_opaque(&self.other);
        Ok(())
    }
}

impl Decode for StateId {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let seqid = decoder.read_u32()?;
        let bytes = decoder.read_fixed_opaque(12)?;
        let other: [u8; 12] = bytes
            .try_into()
            .map_err(|_| crate::xdr::Error::UnexpectedEof {
                needed: 12,
                remaining: bytes.len(),
            })?;
        Ok(Self { seqid, other })
    }
}

/// NFSv4 file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    BlockDevice,
    CharacterDevice,
    Symlink,
    Socket,
    Fifo,
    AttrDir,
    NamedAttr,
    Unknown(u32),
}

impl FileType {
    /// Returns true for regular files.
    pub fn is_file(self) -> bool {
        self == Self::Regular
    }

    /// Returns true for directories.
    pub fn is_dir(self) -> bool {
        self == Self::Directory
    }

    /// Returns true for symbolic links.
    pub fn is_symlink(self) -> bool {
        self == Self::Symlink
    }

    /// Converts a raw `type` attribute value into [`FileType`].
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Regular,
            2 => Self::Directory,
            3 => Self::BlockDevice,
            4 => Self::CharacterDevice,
            5 => Self::Symlink,
            6 => Self::Socket,
            7 => Self::Fifo,
            8 => Self::AttrDir,
            9 => Self::NamedAttr,
            value => Self::Unknown(value),
        }
    }
}

/// NFSv4 attribute bitmap.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bitmap {
    words: Vec<u32>,
}

impl Bitmap {
    /// Creates an empty bitmap.
    pub fn empty() -> Self {
        Self { words: Vec::new() }
    }

    /// Builds a bitmap containing the given attribute numbers.
    pub fn from_attrs(attrs: &[u32]) -> Self {
        let max = attrs.iter().copied().max();
        let mut words = max
            .map(|attr| vec![0; attr as usize / 32 + 1])
            .unwrap_or_default();
        for attr in attrs {
            let word = (*attr / 32) as usize;
            let bit = *attr % 32;
            words[word] |= 1 << bit;
        }
        Self { words }
    }

    /// Builds a bitmap containing requested attributes that are supported.
    pub fn from_supported_attrs(supported: &Self, attrs: &[u32]) -> Self {
        let attrs = attrs
            .iter()
            .copied()
            .filter(|attr| supported.contains(*attr))
            .collect::<Vec<_>>();
        Self::from_attrs(&attrs)
    }

    /// Returns the raw bitmap words.
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    /// Returns true when no attribute bits are set.
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Returns true when `attr` is present in the bitmap.
    pub fn contains(&self, attr: u32) -> bool {
        let word = attr as usize / 32;
        let bit = attr % 32;
        self.words
            .get(word)
            .map(|word| (word & (1 << bit)) != 0)
            .unwrap_or(false)
    }

    fn attrs(&self) -> impl Iterator<Item = u32> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(word_index, word)| {
                (0..32).filter_map(move |bit| {
                    if (word & (1 << bit)) != 0 {
                        Some((word_index as u32) * 32 + bit)
                    } else {
                        None
                    }
                })
            })
    }
}

impl Encode for Bitmap {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_array(&self.words, 128)
    }
}

impl Decode for Bitmap {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            words: decoder.read_array::<u32>(128)?,
        })
    }
}

/// Raw NFSv4 attribute payload.
///
/// High-level APIs usually return parsed structures such as
/// [`BasicAttributes`], [`FsInfo`], [`FsStat`], and [`PathConf`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fattr {
    /// Attribute bitmap describing the encoded values.
    pub attrmask: Bitmap,
    /// XDR-encoded attribute values in bitmap order.
    pub attr_vals: Vec<u8>,
}

impl Fattr {
    /// Creates an empty attribute payload.
    pub fn empty() -> Self {
        Self {
            attrmask: Bitmap::empty(),
            attr_vals: Vec::new(),
        }
    }

    /// Creates an attribute payload that sets file size.
    pub fn size(size: u64) -> Self {
        let mut encoder = Encoder::new();
        encoder.write_u64(size);
        Self {
            attrmask: Bitmap::from_attrs(&[FATTR4_SIZE]),
            attr_vals: encoder.into_bytes(),
        }
    }

    /// Creates an attribute payload that sets mode bits.
    pub fn mode(mode: u32) -> Self {
        let mut encoder = Encoder::new();
        encoder.write_u32(mode);
        Self {
            attrmask: Bitmap::from_attrs(&[FATTR4_MODE]),
            attr_vals: encoder.into_bytes(),
        }
    }

    /// Encodes high-level settable attributes.
    pub fn from_set_attrs(attrs: &SetAttrs) -> Result<Self> {
        let mut attr_ids = Vec::new();
        let mut encoder = Encoder::new();

        if let Some(size) = attrs.size {
            attr_ids.push(FATTR4_SIZE);
            encoder.write_u64(size);
        }
        if let Some(mode) = attrs.mode {
            attr_ids.push(FATTR4_MODE);
            encoder.write_u32(mode);
        }
        if let Some(owner) = &attrs.owner {
            attr_ids.push(FATTR4_OWNER);
            encoder.write_string(owner, NFS4_OPAQUE_LIMIT)?;
        }
        if let Some(owner_group) = &attrs.owner_group {
            attr_ids.push(FATTR4_OWNER_GROUP);
            encoder.write_string(owner_group, NFS4_OPAQUE_LIMIT)?;
        }
        if attrs.access_time != SetTime::DontChange {
            attr_ids.push(FATTR4_TIME_ACCESS_SET);
            encode_set_time(&mut encoder, attrs.access_time);
        }
        if attrs.modify_time != SetTime::DontChange {
            attr_ids.push(FATTR4_TIME_MODIFY_SET);
            encode_set_time(&mut encoder, attrs.modify_time);
        }

        Ok(Self {
            attrmask: Bitmap::from_attrs(&attr_ids),
            attr_vals: encoder.into_bytes(),
        })
    }

    /// Parses a `supported_attrs` response.
    pub fn parse_supported_attrs(&self) -> Result<Bitmap> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut supported = None;

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_SUPPORTED_ATTRS => supported = Some(Bitmap::decode(&mut decoder)?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 supported_attrs attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        supported.ok_or_else(|| {
            Error::Protocol("NFSv4 supported_attrs response did not include attr 0".into())
        })
    }

    /// Parses the basic attribute set used by the high-level client.
    pub fn parse_basic(&self) -> Result<BasicAttributes> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut parsed = BasicAttributes {
            file_type: None,
            change: None,
            size: None,
            fileid: None,
            mode: None,
            numlinks: None,
            owner: None,
            owner_group: None,
            space_used: None,
            access_time: None,
            metadata_time: None,
            modify_time: None,
            raw: self.clone(),
        };

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_TYPE => parsed.file_type = Some(FileType::from_u32(decoder.read_u32()?)),
                FATTR4_CHANGE => parsed.change = Some(decoder.read_u64()?),
                FATTR4_SIZE => parsed.size = Some(decoder.read_u64()?),
                FATTR4_FILEID => parsed.fileid = Some(decoder.read_u64()?),
                FATTR4_MODE => parsed.mode = Some(decoder.read_u32()?),
                FATTR4_NUMLINKS => parsed.numlinks = Some(decoder.read_u32()?),
                FATTR4_OWNER => parsed.owner = Some(decoder.read_string(NFS4_OPAQUE_LIMIT)?),
                FATTR4_OWNER_GROUP => {
                    parsed.owner_group = Some(decoder.read_string(NFS4_OPAQUE_LIMIT)?);
                }
                FATTR4_SPACE_USED => parsed.space_used = Some(decoder.read_u64()?),
                FATTR4_TIME_ACCESS => parsed.access_time = Some(NfsTime::decode(&mut decoder)?),
                FATTR4_TIME_METADATA => {
                    parsed.metadata_time = Some(NfsTime::decode(&mut decoder)?);
                }
                FATTR4_TIME_MODIFY => parsed.modify_time = Some(NfsTime::decode(&mut decoder)?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 basic attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        Ok(parsed)
    }

    pub fn parse_fsstat(&self) -> Result<FsStat> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut parsed = FsStat {
            total_bytes: None,
            free_bytes: None,
            available_bytes: None,
            total_files: None,
            free_files: None,
            available_files: None,
            raw: self.clone(),
        };

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_FILES_AVAIL => parsed.available_files = Some(decoder.read_u64()?),
                FATTR4_FILES_FREE => parsed.free_files = Some(decoder.read_u64()?),
                FATTR4_FILES_TOTAL => parsed.total_files = Some(decoder.read_u64()?),
                FATTR4_SPACE_AVAIL => parsed.available_bytes = Some(decoder.read_u64()?),
                FATTR4_SPACE_FREE => parsed.free_bytes = Some(decoder.read_u64()?),
                FATTR4_SPACE_TOTAL => parsed.total_bytes = Some(decoder.read_u64()?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 fsstat attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        Ok(parsed)
    }

    pub fn parse_fsinfo(&self) -> Result<FsInfo> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut parsed = FsInfo {
            fh_expire_type: None,
            link_support: None,
            symlink_support: None,
            unique_handles: None,
            lease_time_seconds: None,
            can_set_time: None,
            homogeneous: None,
            max_file_size: None,
            max_read: None,
            max_write: None,
            time_delta: None,
            raw: self.clone(),
        };

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_FH_EXPIRE_TYPE => parsed.fh_expire_type = Some(decoder.read_u32()?),
                FATTR4_LINK_SUPPORT => parsed.link_support = Some(decoder.read_bool()?),
                FATTR4_SYMLINK_SUPPORT => parsed.symlink_support = Some(decoder.read_bool()?),
                FATTR4_UNIQUE_HANDLES => parsed.unique_handles = Some(decoder.read_bool()?),
                FATTR4_LEASE_TIME => parsed.lease_time_seconds = Some(decoder.read_u32()?),
                FATTR4_CANSETTIME => parsed.can_set_time = Some(decoder.read_bool()?),
                FATTR4_HOMOGENEOUS => parsed.homogeneous = Some(decoder.read_bool()?),
                FATTR4_MAXFILESIZE => parsed.max_file_size = Some(decoder.read_u64()?),
                FATTR4_MAXREAD => parsed.max_read = Some(decoder.read_u64()?),
                FATTR4_MAXWRITE => parsed.max_write = Some(decoder.read_u64()?),
                FATTR4_TIME_DELTA => parsed.time_delta = Some(NfsTime::decode(&mut decoder)?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 fsinfo attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        Ok(parsed)
    }

    pub fn parse_pathconf(&self) -> Result<PathConf> {
        let mut decoder = Decoder::new(&self.attr_vals);
        let mut parsed = PathConf {
            link_max: None,
            name_max: None,
            no_trunc: None,
            chown_restricted: None,
            case_insensitive: None,
            case_preserving: None,
            raw: self.clone(),
        };

        for attr in self.attrmask.attrs() {
            match attr {
                FATTR4_CASE_INSENSITIVE => parsed.case_insensitive = Some(decoder.read_bool()?),
                FATTR4_CASE_PRESERVING => parsed.case_preserving = Some(decoder.read_bool()?),
                FATTR4_CHOWN_RESTRICTED => {
                    parsed.chown_restricted = Some(decoder.read_bool()?);
                }
                FATTR4_MAXLINK => parsed.link_max = Some(decoder.read_u32()?),
                FATTR4_MAXNAME => parsed.name_max = Some(decoder.read_u32()?),
                FATTR4_NO_TRUNC => parsed.no_trunc = Some(decoder.read_bool()?),
                _ => {
                    return Err(Error::Protocol(format!(
                        "cannot parse unsupported NFSv4 pathconf attribute {attr}"
                    )));
                }
            }
        }

        decoder.finish()?;
        Ok(parsed)
    }
}

impl Decode for Fattr {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            attrmask: Bitmap::decode(decoder)?,
            attr_vals: decoder.read_opaque_vec(NFS4_MAX_IO)?,
        })
    }
}

impl Encode for Fattr {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.attrmask.encode(encoder)?;
        encoder.write_opaque(&self.attr_vals, NFS4_MAX_IO)
    }
}

/// Parsed basic NFSv4 attributes.
///
/// NFSv4 servers may omit attributes. Optional fields reflect exactly what was
/// returned by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicAttributes {
    pub file_type: Option<FileType>,
    pub change: Option<u64>,
    pub size: Option<u64>,
    pub fileid: Option<u64>,
    pub mode: Option<u32>,
    pub numlinks: Option<u32>,
    pub owner: Option<String>,
    pub owner_group: Option<String>,
    pub space_used: Option<u64>,
    pub access_time: Option<NfsTime>,
    pub metadata_time: Option<NfsTime>,
    pub modify_time: Option<NfsTime>,
    pub raw: Fattr,
}

impl BasicAttributes {
    /// Returns the file type or an error if the server omitted it.
    pub fn required_file_type(&self) -> Result<FileType> {
        self.file_type.ok_or_else(|| {
            Error::Protocol("NFSv4 file type attribute was not returned by the server".to_owned())
        })
    }

    /// Returns true when the object is a regular file.
    pub fn is_file(&self) -> Result<bool> {
        Ok(self.required_file_type()?.is_file())
    }

    /// Returns true when the object is a directory.
    pub fn is_dir(&self) -> Result<bool> {
        Ok(self.required_file_type()?.is_dir())
    }

    /// Returns true when the object is a symbolic link.
    pub fn is_symlink(&self) -> Result<bool> {
        Ok(self.required_file_type()?.is_symlink())
    }
}

/// Parsed NFSv4 filesystem capacity attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsStat {
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub total_files: Option<u64>,
    pub free_files: Option<u64>,
    pub available_files: Option<u64>,
    pub raw: Fattr,
}

/// Parsed NFSv4 filesystem capability attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsInfo {
    pub fh_expire_type: Option<u32>,
    pub link_support: Option<bool>,
    pub symlink_support: Option<bool>,
    pub unique_handles: Option<bool>,
    pub lease_time_seconds: Option<u32>,
    pub can_set_time: Option<bool>,
    pub homogeneous: Option<bool>,
    pub max_file_size: Option<u64>,
    pub max_read: Option<u64>,
    pub max_write: Option<u64>,
    pub time_delta: Option<NfsTime>,
    pub raw: Fattr,
}

/// Time-setting mode used by [`SetAttrs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SetTime {
    /// Leave the timestamp unchanged.
    #[default]
    DontChange,
    /// Ask the server to set the timestamp to its current time.
    ServerTime,
    /// Set the timestamp to a client-provided value.
    ClientTime(NfsTime),
}

/// NFSv4 attribute update.
///
/// Fields left empty are not sent to the server. Use constructors such as
/// [`SetAttrs::mode`], [`SetAttrs::size`], and [`SetAttrs::touch`] for common
/// updates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetAttrs {
    pub size: Option<u64>,
    pub mode: Option<u32>,
    pub owner: Option<String>,
    pub owner_group: Option<String>,
    pub access_time: SetTime,
    pub modify_time: SetTime,
}

impl SetAttrs {
    /// Builds an attribute update that sets file size.
    pub fn size(size: u64) -> Self {
        Self {
            size: Some(size),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets POSIX mode bits.
    pub fn mode(mode: u32) -> Self {
        Self {
            mode: Some(mode),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets owner.
    pub fn owner(owner: impl Into<String>) -> Self {
        Self {
            owner: Some(owner.into()),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets owner group.
    pub fn owner_group(owner_group: impl Into<String>) -> Self {
        Self {
            owner_group: Some(owner_group.into()),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets owner and owner group.
    pub fn ownership(owner: impl Into<String>, owner_group: impl Into<String>) -> Self {
        Self {
            owner: Some(owner.into()),
            owner_group: Some(owner_group.into()),
            ..Self::default()
        }
    }

    /// Builds an attribute update that sets access and modification times.
    pub fn times(access_time: Option<NfsTime>, modify_time: Option<NfsTime>) -> Self {
        Self {
            access_time: access_time.map_or(SetTime::DontChange, SetTime::ClientTime),
            modify_time: modify_time.map_or(SetTime::DontChange, SetTime::ClientTime),
            ..Self::default()
        }
    }

    /// Builds an attribute update that asks the server to update both times.
    pub fn touch() -> Self {
        Self {
            access_time: SetTime::ServerTime,
            modify_time: SetTime::ServerTime,
            ..Self::default()
        }
    }
}

/// Parsed NFSv4 path configuration attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathConf {
    pub link_max: Option<u32>,
    pub name_max: Option<u32>,
    pub no_trunc: Option<bool>,
    pub chown_restricted: Option<bool>,
    pub case_insensitive: Option<bool>,
    pub case_preserving: Option<bool>,
    pub raw: Fattr,
}

/// NFSv4 timestamp with second and nanosecond components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfsTime {
    /// Seconds since the Unix epoch.
    pub seconds: i64,
    /// Nanoseconds within the second.
    pub nseconds: u32,
}

impl Decode for NfsTime {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            seconds: decoder.read_i64()?,
            nseconds: decoder.read_u32()?,
        })
    }
}

impl Encode for NfsTime {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_i64(self.seconds);
        encoder.write_u32(self.nseconds);
        Ok(())
    }
}

fn encode_set_time(encoder: &mut Encoder, value: SetTime) {
    match value {
        SetTime::DontChange | SetTime::ServerTime => encoder.write_u32(0),
        SetTime::ClientTime(time) => {
            encoder.write_u32(1);
            encoder.write_i64(time.seconds);
            encoder.write_u32(time.nseconds);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessResult {
    pub supported: u32,
    pub access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOwner {
    pub verifier: Verifier,
    pub owner_id: Vec<u8>,
}

impl Encode for ClientOwner {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_fixed_opaque(&self.verifier);
        encoder.write_opaque(&self.owner_id, NFS4_OPAQUE_LIMIT)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeIdArgs {
    pub client_owner: ClientOwner,
    pub flags: u32,
}

impl Encode for ExchangeIdArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.client_owner.encode(encoder)?;
        encoder.write_u32(self.flags);
        encoder.write_u32(0); // SP4_NONE
        encoder.write_u32(0); // eia_client_impl_id<1>
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeIdResult {
    pub client_id: u64,
    pub sequence_id: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAttrs {
    pub header_pad_size: u32,
    pub max_request_size: u32,
    pub max_response_size: u32,
    pub max_response_size_cached: u32,
    pub max_operations: u32,
    pub max_requests: u32,
    pub rdma_ird: Vec<u32>,
}

impl ChannelAttrs {
    pub fn fore_channel_default() -> Self {
        Self {
            header_pad_size: 0,
            max_request_size: 1024 * 1024,
            max_response_size: 1024 * 1024,
            max_response_size_cached: 0,
            max_operations: 64,
            max_requests: 1,
            rdma_ird: Vec::new(),
        }
    }

    pub fn back_channel_disabled() -> Self {
        Self {
            header_pad_size: 0,
            max_request_size: 0,
            max_response_size: 0,
            max_response_size_cached: 0,
            max_operations: 0,
            max_requests: 0,
            rdma_ird: Vec::new(),
        }
    }
}

impl Encode for ChannelAttrs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.header_pad_size);
        encoder.write_u32(self.max_request_size);
        encoder.write_u32(self.max_response_size);
        encoder.write_u32(self.max_response_size_cached);
        encoder.write_u32(self.max_operations);
        encoder.write_u32(self.max_requests);
        encoder.write_array(&self.rdma_ird, 1)?;
        Ok(())
    }
}

impl Decode for ChannelAttrs {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            header_pad_size: decoder.read_u32()?,
            max_request_size: decoder.read_u32()?,
            max_response_size: decoder.read_u32()?,
            max_response_size_cached: decoder.read_u32()?,
            max_operations: decoder.read_u32()?,
            max_requests: decoder.read_u32()?,
            rdma_ird: decoder.read_array::<u32>(1)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionArgs {
    pub client_id: u64,
    pub sequence_id: u32,
    pub flags: u32,
    pub fore_channel_attrs: ChannelAttrs,
    pub back_channel_attrs: ChannelAttrs,
    pub callback_program: u32,
}

impl Encode for CreateSessionArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.client_id);
        encoder.write_u32(self.sequence_id);
        encoder.write_u32(self.flags);
        self.fore_channel_attrs.encode(encoder)?;
        self.back_channel_attrs.encode(encoder)?;
        encoder.write_u32(self.callback_program);
        encoder.write_u32(0); // callback_sec_parms4<>
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionResult {
    pub session_id: SessionId,
    pub sequence_id: u32,
    pub flags: u32,
    pub fore_channel_attrs: ChannelAttrs,
    pub back_channel_attrs: ChannelAttrs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceArgs {
    pub session_id: SessionId,
    pub sequence_id: u32,
    pub slot_id: u32,
    pub highest_slot_id: u32,
    pub cache_this: bool,
}

impl Encode for SequenceArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_fixed_opaque(&self.session_id);
        encoder.write_u32(self.sequence_id);
        encoder.write_u32(self.slot_id);
        encoder.write_u32(self.highest_slot_id);
        encoder.write_bool(self.cache_this);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceResult {
    pub session_id: SessionId,
    pub sequence_id: u32,
    pub slot_id: u32,
    pub highest_slot_id: u32,
    pub target_highest_slot_id: u32,
    pub status_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOwner {
    pub client_id: u64,
    pub owner: Vec<u8>,
}

impl Encode for OpenOwner {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u64(self.client_id);
        encoder.write_opaque(&self.owner, NFS4_OPAQUE_LIMIT)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenHow {
    NoCreate,
    Unchecked(Fattr),
    Guarded(Fattr),
    Exclusive(Verifier),
}

impl Encode for OpenHow {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::NoCreate => {
                encoder.write_u32(0); // OPEN4_NOCREATE
            }
            Self::Unchecked(attrs) => {
                encoder.write_u32(1); // OPEN4_CREATE
                encoder.write_u32(0); // UNCHECKED4
                attrs.encode(encoder)?;
            }
            Self::Guarded(attrs) => {
                encoder.write_u32(1); // OPEN4_CREATE
                encoder.write_u32(1); // GUARDED4
                attrs.encode(encoder)?;
            }
            Self::Exclusive(verifier) => {
                encoder.write_u32(1); // OPEN4_CREATE
                encoder.write_u32(2); // EXCLUSIVE4
                encoder.write_fixed_opaque(verifier);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenClaim {
    Null(String),
    CurrentFileHandle,
}

impl Encode for OpenClaim {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::Null(name) => {
                encoder.write_u32(0); // CLAIM_NULL
                encoder.write_string(name, NFS4_OPAQUE_LIMIT)?;
            }
            Self::CurrentFileHandle => {
                encoder.write_u32(4); // CLAIM_FH
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenArgs {
    pub seqid: u32,
    pub share_access: u32,
    pub share_deny: u32,
    pub owner: OpenOwner,
    pub openhow: OpenHow,
    pub claim: OpenClaim,
}

impl Encode for OpenArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.seqid);
        encoder.write_u32(self.share_access);
        encoder.write_u32(self.share_deny);
        self.owner.encode(encoder)?;
        self.openhow.encode(encoder)?;
        self.claim.encode(encoder)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenResult {
    pub stateid: StateId,
    pub result_flags: u32,
    pub attrset: Bitmap,
}

/// NFSv4 write stability requested or reported by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableHow {
    /// Server may cache data without committing it to stable storage.
    Unstable,
    /// Server commits file data, but not necessarily metadata.
    DataSync,
    /// Server commits file data and metadata.
    FileSync,
}

impl StableHow {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Unstable => 0,
            Self::DataSync => 1,
            Self::FileSync => 2,
        }
    }

    /// Converts a protocol discriminant into [`StableHow`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Unstable,
            1 => Self::DataSync,
            2 => Self::FileSync,
            _ => return None,
        })
    }
}

/// Result of an NFSv4 WRITE operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    /// Number of bytes written.
    pub count: u32,
    /// Stability level committed by the server.
    pub committed: StableHow,
    /// Server write verifier.
    pub verifier: Verifier,
}

/// Result of an NFSv4 COMMIT operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitResult {
    /// Server write verifier.
    pub verifier: Verifier,
}

/// NFSv4.2 SEEK content selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekContent {
    /// Find data.
    Data,
    /// Find a hole.
    Hole,
}

impl SeekContent {
    /// Returns the protocol discriminant.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Data => 0,
            Self::Hole => 1,
        }
    }

    /// Converts a protocol discriminant into [`SeekContent`].
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::Data,
            1 => Self::Hole,
            _ => return None,
        })
    }
}

/// Result of an NFSv4.2 SEEK operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeekResult {
    /// Whether the server reached EOF before finding the requested content.
    pub eof: bool,
    /// Found offset, or EOF offset when `eof` is true.
    pub offset: u64,
}

impl SeekResult {
    /// Returns the found offset, or `None` when EOF was reached.
    pub fn found_offset(self) -> Option<u64> {
        (!self.eof).then_some(self.offset)
    }
}

/// Object type for raw NFSv4 CREATE operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateKind {
    Directory,
    Symlink(String),
    BlockDevice { major: u32, minor: u32 },
    CharacterDevice { major: u32, minor: u32 },
    Socket,
    Fifo,
}

impl Encode for CreateKind {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        match self {
            Self::Directory => {
                encoder.write_u32(NF4DIR);
            }
            Self::Symlink(target) => {
                encoder.write_u32(NF4LNK);
                encoder.write_string(target, NFS4_OPAQUE_LIMIT)?;
            }
            Self::BlockDevice { major, minor } => {
                encoder.write_u32(NF4BLK);
                encoder.write_u32(*major);
                encoder.write_u32(*minor);
            }
            Self::CharacterDevice { major, minor } => {
                encoder.write_u32(NF4CHR);
                encoder.write_u32(*major);
                encoder.write_u32(*minor);
            }
            Self::Socket => {
                encoder.write_u32(NF4SOCK);
            }
            Self::Fifo => {
                encoder.write_u32(NF4FIFO);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateArgs {
    pub kind: CreateKind,
    pub name: String,
    pub attrs: Fattr,
}

impl Encode for CreateArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        self.kind.encode(encoder)?;
        encoder.write_string(&self.name, NFS4_OPAQUE_LIMIT)?;
        self.attrs.encode(encoder)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    ExchangeId(ExchangeIdArgs),
    CreateSession(CreateSessionArgs),
    DestroySession(SessionId),
    Sequence(SequenceArgs),
    PutRootFh,
    PutFh(FileHandle),
    Lookup(String),
    Access(u32),
    Open(OpenArgs),
    Close {
        seqid: u32,
        stateid: StateId,
    },
    GetFh,
    GetAttr(Bitmap),
    SetAttr {
        stateid: StateId,
        attrs: Fattr,
    },
    Read {
        stateid: StateId,
        offset: u64,
        count: u32,
    },
    Write {
        stateid: StateId,
        offset: u64,
        stable: StableHow,
        data: Vec<u8>,
    },
    Allocate {
        stateid: StateId,
        offset: u64,
        length: u64,
    },
    Deallocate {
        stateid: StateId,
        offset: u64,
        length: u64,
    },
    Seek {
        stateid: StateId,
        offset: u64,
        what: SeekContent,
    },
    Commit {
        offset: u64,
        count: u32,
    },
    ReadDir {
        cookie: u64,
        cookieverf: Verifier,
        dircount: u32,
        maxcount: u32,
        attr_request: Bitmap,
    },
    ReadLink,
    Remove(String),
    Link(String),
    Rename {
        oldname: String,
        newname: String,
    },
    Create(CreateArgs),
    SaveFh,
    RestoreFh,
}

impl Operation {
    pub fn op_code(&self) -> OpCode {
        match self {
            Self::ExchangeId(_) => OpCode::ExchangeId,
            Self::CreateSession(_) => OpCode::CreateSession,
            Self::DestroySession(_) => OpCode::DestroySession,
            Self::Sequence(_) => OpCode::Sequence,
            Self::PutRootFh => OpCode::PutRootFh,
            Self::PutFh(_) => OpCode::PutFh,
            Self::Lookup(_) => OpCode::Lookup,
            Self::Access(_) => OpCode::Access,
            Self::Open(_) => OpCode::Open,
            Self::Close { .. } => OpCode::Close,
            Self::GetFh => OpCode::GetFh,
            Self::GetAttr(_) => OpCode::GetAttr,
            Self::SetAttr { .. } => OpCode::SetAttr,
            Self::Read { .. } => OpCode::Read,
            Self::Write { .. } => OpCode::Write,
            Self::Allocate { .. } => OpCode::Allocate,
            Self::Deallocate { .. } => OpCode::Deallocate,
            Self::Seek { .. } => OpCode::Seek,
            Self::Commit { .. } => OpCode::Commit,
            Self::ReadDir { .. } => OpCode::ReadDir,
            Self::ReadLink => OpCode::ReadLink,
            Self::Remove(_) => OpCode::Remove,
            Self::Link(_) => OpCode::Link,
            Self::Rename { .. } => OpCode::Rename,
            Self::Create(_) => OpCode::Create,
            Self::SaveFh => OpCode::SaveFh,
            Self::RestoreFh => OpCode::RestoreFh,
        }
    }
}

impl Encode for Operation {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_u32(self.op_code().as_u32());
        match self {
            Self::ExchangeId(args) => args.encode(encoder),
            Self::CreateSession(args) => args.encode(encoder),
            Self::DestroySession(session_id) => {
                encoder.write_fixed_opaque(session_id);
                Ok(())
            }
            Self::Sequence(args) => args.encode(encoder),
            Self::PutRootFh | Self::GetFh | Self::ReadLink | Self::SaveFh | Self::RestoreFh => {
                Ok(())
            }
            Self::PutFh(handle) => handle.encode(encoder),
            Self::Lookup(component) => encoder.write_string(component, NFS4_OPAQUE_LIMIT),
            Self::Access(access) => {
                encoder.write_u32(*access);
                Ok(())
            }
            Self::Open(args) => args.encode(encoder),
            Self::Close { seqid, stateid } => {
                encoder.write_u32(*seqid);
                stateid.encode(encoder)
            }
            Self::GetAttr(bitmap) => bitmap.encode(encoder),
            Self::SetAttr { stateid, attrs } => {
                stateid.encode(encoder)?;
                attrs.encode(encoder)
            }
            Self::Read {
                stateid,
                offset,
                count,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u64(*offset);
                encoder.write_u32(*count);
                Ok(())
            }
            Self::Write {
                stateid,
                offset,
                stable,
                data,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u64(*offset);
                encoder.write_u32(stable.as_u32());
                encoder.write_opaque(data, NFS4_MAX_IO)
            }
            Self::Allocate {
                stateid,
                offset,
                length,
            }
            | Self::Deallocate {
                stateid,
                offset,
                length,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u64(*offset);
                encoder.write_u64(*length);
                Ok(())
            }
            Self::Seek {
                stateid,
                offset,
                what,
            } => {
                stateid.encode(encoder)?;
                encoder.write_u64(*offset);
                encoder.write_u32(what.as_u32());
                Ok(())
            }
            Self::Commit { offset, count } => {
                encoder.write_u64(*offset);
                encoder.write_u32(*count);
                Ok(())
            }
            Self::ReadDir {
                cookie,
                cookieverf,
                dircount,
                maxcount,
                attr_request,
            } => {
                encoder.write_u64(*cookie);
                encoder.write_fixed_opaque(cookieverf);
                encoder.write_u32(*dircount);
                encoder.write_u32(*maxcount);
                attr_request.encode(encoder)
            }
            Self::Remove(target) => encoder.write_string(target, NFS4_OPAQUE_LIMIT),
            Self::Link(target) => encoder.write_string(target, NFS4_OPAQUE_LIMIT),
            Self::Rename { oldname, newname } => {
                encoder.write_string(oldname, NFS4_OPAQUE_LIMIT)?;
                encoder.write_string(newname, NFS4_OPAQUE_LIMIT)
            }
            Self::Create(args) => args.encode(encoder),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundArgs {
    pub tag: String,
    pub minor_version: u32,
    pub operations: Vec<Operation>,
}

impl Encode for CompoundArgs {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_string(&self.tag, NFS4_OPAQUE_LIMIT)?;
        encoder.write_u32(self.minor_version);
        encoder.write_array(&self.operations, NFS4_MAX_OPS)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundResponse {
    pub status: Status,
    pub tag: String,
    pub results: Vec<OperationResult>,
}

impl Decode for CompoundResponse {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        Ok(Self {
            status: Status::from_u32(decoder.read_u32()?),
            tag: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
            results: decoder.read_array::<OperationResult>(NFS4_MAX_OPS)?,
        })
    }
}

impl CompoundResponse {
    pub fn ensure_ok(&self) -> Result<()> {
        if self.status.is_ok() {
            Ok(())
        } else if let Some(result) = self.results.last() {
            Err(Error::nfsv4(result.op_name(), result.status()))
        } else {
            Err(Error::nfsv4("COMPOUND", self.status))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationResult {
    ExchangeId {
        status: Status,
        result: Option<ExchangeIdResult>,
    },
    CreateSession {
        status: Status,
        result: Option<CreateSessionResult>,
    },
    Sequence {
        status: Status,
        result: Option<SequenceResult>,
    },
    StatusOnly {
        op: OpCode,
        status: Status,
    },
    Open {
        status: Status,
        result: Option<OpenResult>,
    },
    Close {
        status: Status,
        stateid: Option<StateId>,
    },
    GetFh {
        status: Status,
        handle: Option<FileHandle>,
    },
    GetAttr {
        status: Status,
        attrs: Option<Fattr>,
    },
    Access {
        status: Status,
        result: Option<AccessResult>,
    },
    Read {
        status: Status,
        eof: bool,
        data: Vec<u8>,
    },
    Write {
        status: Status,
        result: Option<WriteResult>,
    },
    Commit {
        status: Status,
        result: Option<CommitResult>,
    },
    Seek {
        status: Status,
        result: Option<SeekResult>,
    },
    ReadDir {
        status: Status,
        cookieverf: Verifier,
        entries: Vec<DirEntry>,
        eof: bool,
    },
    ReadLink {
        status: Status,
        data: Option<String>,
    },
}

impl OperationResult {
    pub fn op_code(&self) -> OpCode {
        match self {
            Self::ExchangeId { .. } => OpCode::ExchangeId,
            Self::CreateSession { .. } => OpCode::CreateSession,
            Self::Sequence { .. } => OpCode::Sequence,
            Self::StatusOnly { op, .. } => *op,
            Self::Open { .. } => OpCode::Open,
            Self::Close { .. } => OpCode::Close,
            Self::GetFh { .. } => OpCode::GetFh,
            Self::GetAttr { .. } => OpCode::GetAttr,
            Self::Access { .. } => OpCode::Access,
            Self::Read { .. } => OpCode::Read,
            Self::Write { .. } => OpCode::Write,
            Self::Commit { .. } => OpCode::Commit,
            Self::Seek { .. } => OpCode::Seek,
            Self::ReadDir { .. } => OpCode::ReadDir,
            Self::ReadLink { .. } => OpCode::ReadLink,
        }
    }

    pub fn op_name(&self) -> &'static str {
        self.op_code().name()
    }

    pub fn status(&self) -> Status {
        match self {
            Self::ExchangeId { status, .. }
            | Self::CreateSession { status, .. }
            | Self::Sequence { status, .. }
            | Self::StatusOnly { status, .. }
            | Self::Open { status, .. }
            | Self::Close { status, .. }
            | Self::GetFh { status, .. }
            | Self::GetAttr { status, .. }
            | Self::Access { status, .. }
            | Self::Read { status, .. }
            | Self::Write { status, .. }
            | Self::Commit { status, .. }
            | Self::Seek { status, .. }
            | Self::ReadDir { status, .. }
            | Self::ReadLink { status, .. } => *status,
        }
    }
}

impl Decode for OperationResult {
    fn decode(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Self> {
        let raw_op = decoder.read_u32()?;
        let op = OpCode::from_u32(raw_op).unwrap_or(OpCode::Illegal);
        let status = Status::from_u32(decoder.read_u32()?);

        match op {
            OpCode::ExchangeId => decode_exchange_id_result(decoder, status),
            OpCode::CreateSession => decode_create_session_result(decoder, status),
            OpCode::Sequence => decode_sequence_result(decoder, status),
            OpCode::Open => decode_open_result(decoder, status),
            OpCode::Close => {
                let stateid = if status.is_ok() {
                    Some(StateId::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::Close { status, stateid })
            }
            OpCode::GetFh => {
                let handle = if status.is_ok() {
                    Some(FileHandle::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::GetFh { status, handle })
            }
            OpCode::GetAttr => {
                let attrs = if status.is_ok() {
                    Some(Fattr::decode(decoder)?)
                } else {
                    None
                };
                Ok(Self::GetAttr { status, attrs })
            }
            OpCode::Access => {
                let result = if status.is_ok() {
                    Some(AccessResult {
                        supported: decoder.read_u32()?,
                        access: decoder.read_u32()?,
                    })
                } else {
                    None
                };
                Ok(Self::Access { status, result })
            }
            OpCode::Read => {
                if status.is_ok() {
                    Ok(Self::Read {
                        status,
                        eof: bool::decode(decoder)?,
                        data: decoder.read_opaque_vec(NFS4_MAX_IO)?,
                    })
                } else {
                    Ok(Self::Read {
                        status,
                        eof: false,
                        data: Vec::new(),
                    })
                }
            }
            OpCode::Write => {
                let result = if status.is_ok() {
                    let count = decoder.read_u32()?;
                    let raw_committed = decoder.read_u32()?;
                    let committed = StableHow::from_u32(raw_committed).ok_or(
                        crate::xdr::Error::InvalidDiscriminant {
                            type_name: "stable_how4",
                            value: raw_committed as i32,
                        },
                    )?;
                    Some(WriteResult {
                        count,
                        committed,
                        verifier: decode_verifier(decoder)?,
                    })
                } else {
                    None
                };
                Ok(Self::Write { status, result })
            }
            OpCode::Commit => {
                let result = if status.is_ok() {
                    Some(CommitResult {
                        verifier: decode_verifier(decoder)?,
                    })
                } else {
                    None
                };
                Ok(Self::Commit { status, result })
            }
            OpCode::Seek => {
                let result = if status.is_ok() {
                    Some(SeekResult {
                        eof: bool::decode(decoder)?,
                        offset: decoder.read_u64()?,
                    })
                } else {
                    None
                };
                Ok(Self::Seek { status, result })
            }
            OpCode::SetAttr => {
                Bitmap::decode(decoder)?;
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::Remove => {
                if status.is_ok() {
                    skip_change_info(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::Link => {
                if status.is_ok() {
                    skip_change_info(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::Rename => {
                if status.is_ok() {
                    skip_change_info(decoder)?;
                    skip_change_info(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::Create => {
                if status.is_ok() {
                    skip_change_info(decoder)?;
                    Bitmap::decode(decoder)?;
                }
                Ok(Self::StatusOnly { op, status })
            }
            OpCode::ReadDir => decode_readdir_result(decoder, status),
            OpCode::ReadLink => {
                let data = if status.is_ok() {
                    Some(decoder.read_string(NFS4_OPAQUE_LIMIT)?)
                } else {
                    None
                };
                Ok(Self::ReadLink { status, data })
            }
            _ => Ok(Self::StatusOnly { op, status }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub cookie: u64,
    pub name: String,
    pub attrs: Fattr,
}

impl DirEntry {
    pub fn basic_attributes(&self) -> Result<BasicAttributes> {
        self.attrs.parse_basic()
    }
}

fn decode_exchange_id_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::ExchangeId {
            status,
            result: None,
        });
    }

    let result = ExchangeIdResult {
        client_id: decoder.read_u64()?,
        sequence_id: decoder.read_u32()?,
        flags: decoder.read_u32()?,
    };
    skip_state_protect_reply(decoder)?;
    skip_server_owner(decoder)?;
    decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
    skip_impl_ids(decoder)?;
    Ok(OperationResult::ExchangeId {
        status,
        result: Some(result),
    })
}

fn decode_create_session_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::CreateSession {
            status,
            result: None,
        });
    }

    let result = CreateSessionResult {
        session_id: decode_session_id(decoder)?,
        sequence_id: decoder.read_u32()?,
        flags: decoder.read_u32()?,
        fore_channel_attrs: ChannelAttrs::decode(decoder)?,
        back_channel_attrs: ChannelAttrs::decode(decoder)?,
    };
    Ok(OperationResult::CreateSession {
        status,
        result: Some(result),
    })
}

fn decode_sequence_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    let result = if status.is_ok() {
        Some(SequenceResult {
            session_id: decode_session_id(decoder)?,
            sequence_id: decoder.read_u32()?,
            slot_id: decoder.read_u32()?,
            highest_slot_id: decoder.read_u32()?,
            target_highest_slot_id: decoder.read_u32()?,
            status_flags: decoder.read_u32()?,
        })
    } else {
        None
    };
    Ok(OperationResult::Sequence { status, result })
}

fn decode_open_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::Open {
            status,
            result: None,
        });
    }

    let stateid = StateId::decode(decoder)?;
    skip_change_info(decoder)?;
    let result_flags = decoder.read_u32()?;
    let attrset = Bitmap::decode(decoder)?;
    skip_open_delegation(decoder)?;
    Ok(OperationResult::Open {
        status,
        result: Some(OpenResult {
            stateid,
            result_flags,
            attrset,
        }),
    })
}

fn skip_change_info(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    decoder.read_bool()?;
    decoder.read_u64()?;
    decoder.read_u64()?;
    Ok(())
}

fn skip_open_delegation(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    match decoder.read_u32()? {
        0 => Ok(()),
        1 => {
            StateId::decode(decoder)?;
            decoder.read_bool()?;
            skip_nfsace(decoder)
        }
        2 => {
            StateId::decode(decoder)?;
            decoder.read_bool()?;
            match decoder.read_u32()? {
                1 => {
                    decoder.read_u64()?;
                }
                2 => {
                    decoder.read_u32()?;
                    decoder.read_u32()?;
                }
                value => {
                    return Err(crate::xdr::Error::InvalidDiscriminant {
                        type_name: "limit_by4",
                        value: value as i32,
                    });
                }
            }
            skip_nfsace(decoder)
        }
        3 => {
            match decoder.read_u32()? {
                1 | 2 => {
                    decoder.read_bool()?;
                }
                _ => {}
            }
            Ok(())
        }
        value => Err(crate::xdr::Error::InvalidDiscriminant {
            type_name: "open_delegation_type4",
            value: value as i32,
        }),
    }
}

fn skip_nfsace(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    decoder.read_u32()?;
    decoder.read_u32()?;
    decoder.read_u32()?;
    decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
    Ok(())
}

fn decode_readdir_result(
    decoder: &mut Decoder<'_>,
    status: Status,
) -> crate::xdr::Result<OperationResult> {
    if !status.is_ok() {
        return Ok(OperationResult::ReadDir {
            status,
            cookieverf: [0; NFS4_VERIFIER_SIZE],
            entries: Vec::new(),
            eof: false,
        });
    }

    let cookieverf = decode_verifier(decoder)?;
    let mut entries = Vec::new();
    while bool::decode(decoder)? {
        if entries.len() >= NFS4_MAX_DIR_ENTRIES {
            return Err(crate::xdr::Error::LengthLimitExceeded {
                len: entries.len() + 1,
                max: NFS4_MAX_DIR_ENTRIES,
            });
        }
        entries.push(DirEntry {
            cookie: decoder.read_u64()?,
            name: decoder.read_string(NFS4_OPAQUE_LIMIT)?,
            attrs: Fattr::decode(decoder)?,
        });
    }
    let eof = bool::decode(decoder)?;
    Ok(OperationResult::ReadDir {
        status,
        cookieverf,
        entries,
        eof,
    })
}

fn skip_state_protect_reply(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    match decoder.read_u32()? {
        0 => Ok(()),
        1 => {
            Bitmap::decode(decoder)?;
            Bitmap::decode(decoder)?;
            Ok(())
        }
        2 => {
            Bitmap::decode(decoder)?;
            Bitmap::decode(decoder)?;
            decoder.read_u32()?;
            decoder.read_u32()?;
            decoder.read_u32()?;
            decoder.read_u32()?;
            let handle_count = decoder.read_u32()? as usize;
            for _ in 0..handle_count.min(1024) {
                decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
            }
            Ok(())
        }
        value => Err(crate::xdr::Error::InvalidDiscriminant {
            type_name: "state_protect_how4",
            value: value as i32,
        }),
    }
}

fn skip_server_owner(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    decoder.read_u64()?;
    decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
    Ok(())
}

fn skip_impl_ids(decoder: &mut Decoder<'_>) -> crate::xdr::Result<()> {
    let count = decoder.read_u32()? as usize;
    if count > 1 {
        return Err(crate::xdr::Error::LengthLimitExceeded { len: count, max: 1 });
    }
    for _ in 0..count {
        decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
        decoder.read_opaque(NFS4_OPAQUE_LIMIT)?;
        decoder.read_i64()?;
        decoder.read_u32()?;
    }
    Ok(())
}

pub(crate) fn decode_verifier(decoder: &mut Decoder<'_>) -> crate::xdr::Result<Verifier> {
    let bytes = decoder.read_fixed_opaque(NFS4_VERIFIER_SIZE)?;
    bytes
        .try_into()
        .map_err(|_| crate::xdr::Error::UnexpectedEof {
            needed: NFS4_VERIFIER_SIZE,
            remaining: bytes.len(),
        })
}

fn decode_session_id(decoder: &mut Decoder<'_>) -> crate::xdr::Result<SessionId> {
    let bytes = decoder.read_fixed_opaque(NFS4_SESSIONID_SIZE)?;
    bytes
        .try_into()
        .map_err(|_| crate::xdr::Error::UnexpectedEof {
            needed: NFS4_SESSIONID_SIZE,
            remaining: bytes.len(),
        })
}
