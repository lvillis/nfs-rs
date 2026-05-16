//! Blocking NFSv4 client.
//!
//! The client creates an NFSv4 session and executes path-oriented operations
//! against the server's v4 pseudo-filesystem.
//!
//! ```no_run
//! let mut client = nfs::v4::blocking::Client::connect("127.0.0.1")?;
//! client.write("/export/object.txt", b"payload")?;
//! assert_eq!(client.read("/export/object.txt")?, b"payload");
//! client.shutdown()?;
//! # Ok::<(), nfs::Error>(())
//! ```

use std::io::{Read, Write};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::retry::RetryPolicy;
use crate::rpc::{Auth, AuthSys, RpcClient, max_record_size_for_payloads};
use crate::v4::client::{
    SpaceOp, advance_offset, attrs_require_open_state, dir_page_from_entries, ensure_last_status,
    ensure_reclaim_complete, finish_with_close, join_path,
    operations_can_replay_after_session_recovery, path_components, path_ops, response_access,
    response_commit, response_consumed_owner_seqid, response_create_session, response_exchange_id,
    response_getattr, response_getfh, response_has_retryable_status, response_open, response_read,
    response_readdir, response_readlink, response_requires_session_recovery, response_seek,
    response_write, sequence_succeeded, session_max_operations, session_payload_limit,
    session_recovery_error, split_parent, temporary_sibling_path,
    validate_session_compound_operation_count, verifier_from_time,
};
use crate::v4::proto::*;
use crate::v4::{
    clamp_io_size, default_open_owner, default_owner_id, negotiated_minor_versions,
    require_minor_version, validate_host, validate_max_dir_entries, validate_minor_version,
    validate_open_owner, validate_owner_id, validate_port, validate_transfer_size,
};
use crate::xdr::{Decode, Decoder};

const DEFAULT_IO_SIZE: u32 = 128 * 1024;
const DEFAULT_DIR_SIZE: u32 = 128 * 1024;

pub use crate::v4::client::{DirEntry, DirPage, DirPageCursor};

/// Builder for a blocking NFSv4 [`Client`].
///
/// Defaults are conservative: AUTH_SYS credentials from the current process,
/// port 2049, a 30 second timeout, generated client/open owner identifiers,
/// 128 KiB transfer limits, and the default [`RetryPolicy`].
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    host: String,
    auth: AuthSys,
    timeout: Option<Duration>,
    port: u16,
    owner_id: Vec<u8>,
    open_owner: Vec<u8>,
    client_owner_verifier: Verifier,
    read_size: u32,
    write_size: u32,
    dir_size: u32,
    max_dir_entries: usize,
    max_minor_version: u32,
    retry_policy: RetryPolicy,
}

impl ClientBuilder {
    /// Creates a builder for an NFSv4 server host.
    pub fn new(host: impl Into<String>) -> Self {
        let host = host.into();
        Self {
            owner_id: default_owner_id(&host),
            open_owner: default_open_owner(&host),
            client_owner_verifier: verifier_from_time(),
            host,
            auth: AuthSys::current(),
            timeout: Some(Duration::from_secs(30)),
            port: NFS4_PORT,
            read_size: DEFAULT_IO_SIZE,
            write_size: DEFAULT_IO_SIZE,
            dir_size: DEFAULT_DIR_SIZE,
            max_dir_entries: NFS4_MAX_DIR_ENTRIES,
            max_minor_version: NFS4_MINOR_VERSION_LATEST,
            retry_policy: RetryPolicy::default(),
        }
    }

    /// Sets AUTH_SYS credentials for RPC calls.
    pub fn auth_sys(mut self, auth: AuthSys) -> Self {
        self.auth = auth;
        self
    }

    /// Sets socket connect/read/write timeout.
    ///
    /// `None` disables socket timeouts.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the NFSv4 TCP port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the client owner id used during `EXCHANGE_ID`.
    pub fn owner_id(mut self, owner_id: impl Into<Vec<u8>>) -> Self {
        self.owner_id = owner_id.into();
        self
    }

    /// Sets the open owner id used for `OPEN` sequencing.
    pub fn open_owner(mut self, open_owner: impl Into<Vec<u8>>) -> Self {
        self.open_owner = open_owner.into();
        self
    }

    /// Sets the client owner verifier used during `EXCHANGE_ID`.
    pub fn client_owner_verifier(mut self, verifier: Verifier) -> Self {
        self.client_owner_verifier = verifier;
        self
    }

    /// Sets both read and write transfer limits.
    pub fn io_size(mut self, size: u32) -> Self {
        self.read_size = size;
        self.write_size = size;
        self
    }

    /// Sets the read transfer limit.
    pub fn read_size(mut self, size: u32) -> Self {
        self.read_size = size;
        self
    }

    /// Sets the write transfer limit.
    pub fn write_size(mut self, size: u32) -> Self {
        self.write_size = size;
        self
    }

    /// Sets the maximum READDIR response size requested.
    pub fn dir_size(mut self, size: u32) -> Self {
        self.dir_size = size;
        self
    }

    /// Sets the maximum number of directory entries a single high-level call may collect.
    pub fn max_dir_entries(mut self, max_dir_entries: usize) -> Self {
        self.max_dir_entries = max_dir_entries;
        self
    }

    /// Sets the highest NFSv4 minor version the client may negotiate.
    ///
    /// The session client supports NFSv4.1 and NFSv4.2. By default it tries
    /// NFSv4.2 first and falls back to NFSv4.1 when the server rejects the
    /// newer minor version.
    pub fn max_minor_version(mut self, minor_version: u32) -> Self {
        self.max_minor_version = minor_version;
        self
    }

    /// Sets retry behavior for retryable transport and protocol responses.
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Connects, creates an NFSv4 session, and returns a ready client.
    pub fn connect(self) -> Result<Client> {
        Client::connect_with_builder(self)
    }
}

/// Blocking, path-oriented NFSv4 client.
///
/// `Client` owns a session and handles sequencing, retryable delay responses,
/// and one-shot session recovery for recoverable session failures. Paths are
/// absolute paths in the server's v4 pseudo-filesystem.
#[derive(Debug)]
pub struct Client {
    rpc: RpcClient,
    builder: ClientBuilder,
    client_id: u64,
    session_id: SessionId,
    sequence_id: u32,
    open_seqid: u32,
    open_owner: Vec<u8>,
    minor_version: u32,
    max_operations: usize,
    max_request_size: u32,
    max_response_size: u32,
    root_fsinfo: Option<FsInfo>,
    read_size: u32,
    write_size: u32,
    dir_size: u32,
    max_dir_entries: usize,
    retry_policy: RetryPolicy,
}

impl Client {
    /// Connects to an NFSv4 server using default builder options.
    pub fn connect(host: impl Into<String>) -> Result<Self> {
        ClientBuilder::new(host).connect()
    }

    /// Creates a builder for the given server host.
    pub fn builder(host: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(host)
    }

    /// Returns the negotiated NFSv4 minor version.
    pub fn minor_version(&self) -> u32 {
        self.minor_version
    }

    /// Resolves a path and returns success if it exists.
    pub fn lookup(&mut self, path: &str) -> Result<()> {
        self.compound(path_ops(path, Vec::new())?).map(|_| ())
    }

    /// Returns whether a path exists.
    pub fn exists(&mut self, path: &str) -> Result<bool> {
        match self.lookup(path) {
            Ok(_) => Ok(true),
            Err(Error::NfsV4 {
                status: Status::NoEnt,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Reads basic attributes for a path.
    pub fn getattr(&mut self, path: &str) -> Result<BasicAttributes> {
        self.get_supported_attr_values(path, FATTR4_BASIC_ATTRS)?
            .parse_basic()
    }

    /// Alias for [`Client::getattr`].
    pub fn metadata(&mut self, path: &str) -> Result<BasicAttributes> {
        self.getattr(path)
    }

    /// Returns the remote file type for a path.
    pub fn file_type(&mut self, path: &str) -> Result<FileType> {
        self.metadata(path)?.required_file_type()
    }

    /// Returns true when the path is a regular file.
    pub fn is_file(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path)?.is_file())
    }

    /// Returns true when the path is a directory.
    pub fn is_dir(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path)?.is_dir())
    }

    /// Returns true when the path is a symbolic link.
    pub fn is_symlink(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path)?.is_symlink())
    }

    /// Returns the attribute bitmap supported by the server for a path.
    pub fn supported_attrs(&mut self, path: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self.compound(path_ops(path, vec![Operation::GetAttr(attrs)])?)?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    /// Reads filesystem capacity attributes for a path.
    pub fn fsstat(&mut self, path: &str) -> Result<FsStat> {
        self.get_supported_attr_values(path, FATTR4_FSSTAT_ATTRS)?
            .parse_fsstat()
    }

    /// Reads filesystem capability attributes for a path.
    pub fn fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        self.get_supported_attr_values(path, FATTR4_FSINFO_ATTRS)?
            .parse_fsinfo()
    }

    /// Reads path configuration limits for a path.
    pub fn pathconf(&mut self, path: &str) -> Result<PathConf> {
        self.get_supported_attr_values(path, FATTR4_PATHCONF_ATTRS)?
            .parse_pathconf()
    }

    /// Returns root filesystem information discovered at connect time, if available.
    pub fn root_fsinfo(&self) -> Option<&FsInfo> {
        self.root_fsinfo.as_ref()
    }

    /// Recreates the session using the original builder configuration.
    pub fn reconnect(&mut self) -> Result<()> {
        let previous_client_id = self.client_id;
        let previous_open_seqid = self.open_seqid;
        let previous_root_fsinfo = self.root_fsinfo.clone();

        let mut rebuilt = Self::connect_session(self.builder.clone())?;
        if rebuilt.client_id == previous_client_id {
            rebuilt.open_seqid = previous_open_seqid;
        }
        if let Some(fsinfo) = previous_root_fsinfo {
            rebuilt.apply_fsinfo_limits(&fsinfo);
            rebuilt.root_fsinfo = Some(fsinfo);
        }
        *self = rebuilt;
        Ok(())
    }

    /// Checks server-granted access bits for a path.
    pub fn access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let response = self.compound(path_ops(path, vec![Operation::Access(access)])?)?;
        response_access(&response)
    }

    /// Reads an entire file into memory.
    pub fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_to_end(&opened);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Streams an entire file into a local writer.
    pub fn read_to_writer<W: Write + ?Sized>(&mut self, path: &str, writer: &mut W) -> Result<u64> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_to_writer(&opened, writer);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Streams a byte range into a local writer.
    pub fn read_range_to_writer<W: Write + ?Sized>(
        &mut self,
        path: &str,
        offset: u64,
        count: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_range_to_writer(&opened, offset, count, writer);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads a byte range into memory.
    pub fn read_range(&mut self, path: &str, offset: u64, count: u64) -> Result<Vec<u8>> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_range_vec(&opened, offset, count);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads up to `count` bytes at `offset`.
    pub fn read_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.read_opened_range(&opened, offset, count);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Reads exactly `count` bytes at `offset`, failing if EOF is reached first.
    pub fn read_exact_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let data = self.read_at(path, offset, count)?;
        if data.len() != count as usize {
            return Err(Error::Protocol(format!(
                "NFSv4 READ returned {} bytes before EOF; expected {count}",
                data.len()
            )));
        }
        Ok(data)
    }

    /// Executes an NFSv4.2 SEEK operation.
    pub fn seek(&mut self, path: &str, offset: u64, what: SeekContent) -> Result<SeekResult> {
        require_minor_version("SEEK", self.minor_version, NFS4_MINOR_VERSION_V42)?;
        let opened = self.open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let result = self.seek_opened(&opened, offset, what);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Finds the next data offset at or after `offset`.
    pub fn seek_data(&mut self, path: &str, offset: u64) -> Result<Option<u64>> {
        self.seek(path, offset, SeekContent::Data)
            .map(SeekResult::found_offset)
    }

    /// Finds the next hole offset at or after `offset`.
    pub fn seek_hole(&mut self, path: &str, offset: u64) -> Result<Option<u64>> {
        self.seek(path, offset, SeekContent::Hole)
            .map(SeekResult::found_offset)
    }

    /// Reads the target of a symbolic link.
    pub fn read_link(&mut self, path: &str) -> Result<String> {
        let response = self.compound(path_ops(path, vec![Operation::ReadLink])?)?;
        response_readlink(&response)
    }

    fn read_opened_to_end(&mut self, opened: &OpenedFile) -> Result<Vec<u8>> {
        let mut offset = 0;
        let mut out = Vec::new();
        loop {
            let (eof, data) = self.read_opened_at(opened, offset, self.read_size)?;
            if data.len() > self.read_size as usize {
                return Err(Error::Protocol(format!(
                    "NFSv4 READ returned {} bytes for a {} byte request",
                    data.len(),
                    self.read_size
                )));
            }
            if data.is_empty() {
                if eof {
                    return Ok(out);
                }
                return Err(Error::Protocol(
                    "NFSv4 READ returned no data before EOF".into(),
                ));
            }
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            out.extend_from_slice(&data);
            if eof {
                return Ok(out);
            }
        }
    }

    fn read_opened_to_writer<W: Write + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        writer: &mut W,
    ) -> Result<u64> {
        let mut offset = 0;
        let mut total = 0;
        loop {
            let (eof, data) = self.read_opened_at(opened, offset, self.read_size)?;
            if data.len() > self.read_size as usize {
                return Err(Error::Protocol(format!(
                    "NFSv4 READ returned {} bytes for a {} byte request",
                    data.len(),
                    self.read_size
                )));
            }
            if data.is_empty() {
                if eof {
                    return Ok(total);
                }
                return Err(Error::Protocol(
                    "NFSv4 READ returned no data before EOF".into(),
                ));
            }
            writer.write_all(&data)?;
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            advance_offset(&mut total, data.len(), "NFSv4 READ total")?;
            if eof {
                return Ok(total);
            }
        }
    }

    fn read_opened_range(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        self.read_opened_range_vec(opened, offset, u64::from(count))
    }

    fn read_opened_range_vec(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>> {
        let capacity = usize::try_from(count).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity.min(self.read_size as usize));
        self.read_opened_range_to_writer(opened, offset, count, &mut out)?;
        Ok(out)
    }

    fn read_opened_range_to_writer<W: Write + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        mut remaining: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let mut total = 0;
        while remaining > 0 {
            let request = u64::from(self.read_size).min(remaining) as u32;
            let (eof, data) = self.read_opened_at(opened, offset, request)?;
            if data.len() > request as usize {
                return Err(Error::Protocol(format!(
                    "NFSv4 READ returned {} bytes for a {request} byte request",
                    data.len()
                )));
            }
            if data.is_empty() {
                if eof {
                    return Ok(total);
                }
                return Err(Error::Protocol(
                    "NFSv4 READ returned no data before EOF".into(),
                ));
            }
            writer.write_all(&data)?;
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            advance_offset(&mut total, data.len(), "NFSv4 READ total")?;
            remaining -= data.len() as u64;
            if eof {
                return Ok(total);
            }
        }
        Ok(total)
    }

    /// Replaces or creates a file with `data`.
    pub fn write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_with_mode(path, data, 0o644)
    }

    /// Replaces or creates a file with an explicit mode when created.
    pub fn write_with_mode(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let opened = self.open(
            path,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
        )?;

        let result = self
            .set_opened_size(&opened, 0)
            .and_then(|()| self.write_opened_at(&opened, 0, data));
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Replaces or creates a file by streaming from a local reader.
    pub fn write_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_from_reader_with_mode(path, reader, 0o644)
    }

    /// Replaces or creates a file from a reader with an explicit mode when created.
    pub fn write_from_reader_with_mode<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let opened = self.open(
            path,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
        )?;

        let result = self
            .set_opened_size(&opened, 0)
            .and_then(|()| self.write_opened_from_reader(&opened, reader));
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Writes a file through a temporary sibling and renames it into place.
    pub fn write_atomic(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_atomic_with_mode(path, data, 0o644)
    }

    /// Atomic write with an explicit mode for the temporary file.
    pub fn write_atomic_with_mode(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self.open(
            &temp,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
        ) {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_at(&opened, 0, data);
                let close_result = self.close(opened);
                finish_with_close(write_result, close_result)
                    .and_then(|()| self.rename(&temp, path))
            }
            Err(err) => Err(err),
        };

        if result.is_err() && created {
            let _ = self.remove(&temp);
        }
        result
    }

    /// Atomic write by streaming from a local reader.
    pub fn write_atomic_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_atomic_from_reader_with_mode(path, reader, 0o644)
    }

    /// Atomic reader-based write with an explicit mode for the temporary file.
    pub fn write_atomic_from_reader_with_mode<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self.open(
            &temp,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
        ) {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_from_reader(&opened, reader);
                let close_result = self.close(opened);
                match finish_with_close(write_result, close_result) {
                    Ok(written) => self.rename(&temp, path).map(|()| written),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };

        if result.is_err() && created {
            let _ = self.remove(&temp);
        }
        result
    }

    /// Appends bytes to an existing file and returns bytes written.
    pub fn append(&mut self, path: &str, data: &[u8]) -> Result<u64> {
        let offset = self.metadata(path)?.size.ok_or_else(|| {
            Error::Protocol("NFSv4 size attribute is required for append".to_owned())
        })?;
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = (|| {
            self.write_opened_at(&opened, offset, data)?;
            let mut written = 0;
            advance_offset(&mut written, data.len(), "NFSv4 APPEND")?;
            Ok(written)
        })();
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Appends bytes from a local reader and returns bytes written.
    pub fn append_from_reader<R: Read + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        let offset = self.metadata(path)?.size.ok_or_else(|| {
            Error::Protocol("NFSv4 size attribute is required for append".to_owned())
        })?;
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.write_opened_from_reader_at(&opened, offset, reader);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Truncates or extends a file to `size` bytes.
    pub fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.set_opened_size(&opened, size);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Allocates storage for a byte range when supported by the server.
    pub fn allocate(&mut self, path: &str, offset: u64, length: u64) -> Result<()> {
        self.update_allocation(path, offset, length, SpaceOp::Allocate)
    }

    /// Deallocates storage for a byte range when supported by the server.
    pub fn deallocate(&mut self, path: &str, offset: u64, length: u64) -> Result<()> {
        self.update_allocation(path, offset, length, SpaceOp::Deallocate)
    }

    /// Applies NFSv4 attributes to a path.
    pub fn setattr(&mut self, path: &str, attrs: &SetAttrs) -> Result<()> {
        let attrs = Fattr::from_set_attrs(attrs)?;
        if attrs.attrmask.is_empty() {
            return Ok(());
        }
        if attrs_require_open_state(&attrs) {
            let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
            let result = self.set_opened_attrs(&opened, attrs);
            let close_result = self.close(opened);
            return finish_with_close(result, close_result);
        }
        let response = self.compound(path_ops(
            path,
            vec![Operation::SetAttr {
                stateid: StateId::anonymous(),
                attrs,
            }],
        )?)?;
        self.ensure_status(response, "SETATTR")
    }

    /// Sets POSIX mode bits when the server supports the mode attribute.
    pub fn set_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.setattr(path, &SetAttrs::mode(mode))
    }

    /// Sets the owner string.
    pub fn set_owner(&mut self, path: &str, owner: impl Into<String>) -> Result<()> {
        self.setattr(path, &SetAttrs::owner(owner))
    }

    /// Sets the owner group string.
    pub fn set_owner_group(&mut self, path: &str, owner_group: impl Into<String>) -> Result<()> {
        self.setattr(path, &SetAttrs::owner_group(owner_group))
    }

    /// Sets owner and owner group strings.
    pub fn set_ownership(
        &mut self,
        path: &str,
        owner: impl Into<String>,
        owner_group: impl Into<String>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::ownership(owner, owner_group))
    }

    /// Sets access and modification times.
    pub fn set_times(
        &mut self,
        path: &str,
        access_time: Option<NfsTime>,
        modify_time: Option<NfsTime>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::times(access_time, modify_time))
    }

    /// Updates access and modification times to the server time.
    pub fn touch(&mut self, path: &str) -> Result<()> {
        self.setattr(path, &SetAttrs::touch())
    }

    /// Writes bytes at `offset`.
    pub fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.write_opened_at(&opened, offset, data);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    /// Copies a file, replacing or creating the destination.
    pub fn copy(&mut self, from: &str, to: &str) -> Result<u64> {
        if path_components(from)? == path_components(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let mode = self.metadata(from)?.mode.unwrap_or(0o644) & 0o7777;
        let source = self.open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let target = match self.open(
            to,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Unchecked(Fattr::mode(mode)),
        ) {
            Ok(target) => target,
            Err(err) => {
                let _ = self.close(source);
                return Err(err);
            }
        };

        let result = self
            .set_opened_size(&target, 0)
            .and_then(|()| self.copy_opened(&source, &target));
        let target_close = self.close(target);
        let source_close = self.close(source);
        match result {
            Ok(copied) => {
                target_close?;
                source_close?;
                Ok(copied)
            }
            Err(err) => Err(err),
        }
    }

    /// Copies through a temporary sibling and renames it into place.
    pub fn copy_atomic(&mut self, from: &str, to: &str) -> Result<u64> {
        if path_components(from)? == path_components(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let mode = self.metadata(from)?.mode.unwrap_or(0o644) & 0o7777;
        let temp = temporary_sibling_path(to)?;
        let source = self.open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)?;
        let target = match self.open(
            &temp,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
        ) {
            Ok(target) => target,
            Err(err) => {
                let _ = self.close(source);
                return Err(err);
            }
        };

        let copy_result = self.copy_opened(&source, &target);
        let target_close = self.close(target);
        let source_close = self.close(source);
        let result = match copy_result {
            Ok(copied) => {
                target_close?;
                source_close?;
                self.rename(&temp, to).map(|()| copied)
            }
            Err(err) => Err(err),
        };

        if result.is_err() {
            let _ = self.remove(&temp);
        }
        result
    }

    /// Commits previously unstable writes for a byte range.
    pub fn commit(&mut self, path: &str, offset: u64, count: u32) -> Result<CommitResult> {
        let response = self.compound(path_ops(path, vec![Operation::Commit { offset, count }])?)?;
        response_commit(&response)
    }

    /// Creates a new file using default mode `0o644`.
    pub fn create(&mut self, path: &str) -> Result<()> {
        self.create_new(path)
    }

    /// Creates a new file and fails if it already exists.
    pub fn create_new(&mut self, path: &str) -> Result<()> {
        self.create_new_with_mode(path, 0o644)
    }

    /// Creates or replaces a file with an explicit mode.
    pub fn create_with_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_new_with_mode(path, mode)
    }

    /// Creates a new file with an explicit mode and fails if it already exists.
    pub fn create_new_with_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        let opened = self.open(
            path,
            OPEN4_SHARE_ACCESS_BOTH,
            OpenHow::Guarded(Fattr::mode(mode)),
        )?;
        self.close(opened)
    }

    /// Creates a directory.
    pub fn mkdir(&mut self, path: &str, mode: u32) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Create(CreateArgs {
            kind: CreateKind::Directory,
            name,
            attrs: Fattr::mode(mode),
        }));

        let response = self.compound(ops)?;
        self.ensure_status_for(&response, "CREATE")
    }

    /// Creates a directory and missing parents, like `mkdir -p`.
    pub fn create_dir_all(&mut self, path: &str, mode: u32) -> Result<()> {
        let components = path_components(path)?;
        let mut current = String::from("/");
        for component in components {
            current = join_path(&current, component);
            match self.metadata(&current) {
                Ok(attrs) => self.ensure_directory_type(&current, attrs.file_type)?,
                Err(Error::NfsV4 {
                    status: Status::NoEnt,
                    ..
                }) => match self.mkdir(&current, mode) {
                    Ok(_) => {}
                    Err(Error::NfsV4 {
                        status: Status::Exist,
                        ..
                    }) => {
                        let attrs = self.metadata(&current)?;
                        self.ensure_directory_type(&current, attrs.file_type)?;
                    }
                    Err(err) => return Err(err),
                },
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// Creates a symbolic link at `path` pointing to `target`.
    pub fn symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Create(CreateArgs {
            kind: CreateKind::Symlink(target.to_owned()),
            name,
            attrs: Fattr::empty(),
        }));

        let response = self.compound(ops)?;
        self.ensure_status_for(&response, "CREATE")
    }

    /// Creates a hard link.
    pub fn hard_link(&mut self, existing: &str, link: &str) -> Result<()> {
        let existing_components = path_components(existing)?;
        let (link_parent, link_name) = split_parent(link)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in existing_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::SaveFh);
        ops.push(Operation::PutRootFh);
        for component in link_parent {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Link(link_name));

        let response = self.compound(ops)?;
        self.ensure_status(response, "LINK")
    }

    /// Removes a non-directory entry.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Remove(name));

        let response = self.compound(ops)?;
        self.ensure_status(response, "REMOVE")
    }

    /// Removes a non-directory entry if it exists.
    pub fn remove_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove(path) {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Removes an empty directory.
    pub fn rmdir(&mut self, path: &str) -> Result<()> {
        self.remove(path)
    }

    /// Removes an empty directory if it exists.
    pub fn rmdir_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.rmdir(path) {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Recursively removes a file tree.
    ///
    /// The NFSv4 pseudo-filesystem root itself cannot be removed through this method.
    pub fn remove_all(&mut self, path: &str) -> Result<()> {
        if path_components(path)?.is_empty() {
            return Err(Error::InvalidPath(path.to_owned()));
        }

        enum RemoveTask {
            Visit(String, Option<FileType>),
            RemoveDir(String),
        }

        let file_type = self.metadata(path)?.file_type;
        let mut stack = vec![RemoveTask::Visit(path.to_owned(), file_type)];
        while let Some(task) = stack.pop() {
            match task {
                RemoveTask::Visit(path, file_type) => {
                    if self.path_is_directory(&path, file_type)? {
                        stack.push(RemoveTask::RemoveDir(path.clone()));
                        let entries = self.read_dir(&path)?;
                        for entry in entries.into_iter().rev() {
                            if entry.name == "." || entry.name == ".." {
                                continue;
                            }
                            let child = join_path(&path, &entry.name);
                            let child_type = entry.basic_attributes()?.file_type;
                            stack.push(RemoveTask::Visit(child, child_type));
                        }
                    } else {
                        self.remove(&path)?;
                    }
                }
                RemoveTask::RemoveDir(path) => self.rmdir(&path)?,
            }
        }

        Ok(())
    }

    /// Recursively removes a file tree if it exists.
    pub fn remove_all_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove_all(path) {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Renames or moves a path.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let (from_parent, from_name) = split_parent(from)?;
        let (to_parent, to_name) = split_parent(to)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in from_parent {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::SaveFh);
        ops.push(Operation::PutRootFh);
        for component in to_parent {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Rename {
            oldname: from_name,
            newname: to_name,
        });

        let response = self.compound(ops)?;
        self.ensure_status(response, "RENAME")
    }

    /// Reads all entries in a directory, subject to the client's entry limit.
    pub fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.read_dir_with_limit(path, self.max_dir_entries)
    }

    /// Reads all entries in a directory with a per-call entry limit.
    pub fn read_dir_limited(&mut self, path: &str, max_entries: usize) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.read_dir_with_limit(path, max_entries.min(self.max_dir_entries))
    }

    /// Reads one page of directory entries.
    pub fn read_dir_page(&mut self, path: &str, cursor: Option<DirPageCursor>) -> Result<DirPage> {
        self.read_dir_page_limited(path, cursor, self.max_dir_entries)
    }

    /// Reads one page of directory entries with a per-page entry limit.
    pub fn read_dir_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let attr_request = self.supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let cursor = cursor.unwrap_or_default();
        let response = self.compound(path_ops(
            path,
            vec![Operation::ReadDir {
                cookie: cursor.cookie,
                cookieverf: cursor.cookieverf,
                dircount: (self.dir_size / 2).max(1),
                maxcount: self.dir_size,
                attr_request,
            }],
        )?)?;
        let (cookieverf, entries, eof) = response_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, max_entries)
    }

    fn read_dir_with_limit(&mut self, path: &str, max_entries: usize) -> Result<Vec<DirEntry>> {
        let attr_request = self.supported_attr_request(path, FATTR4_BASIC_ATTRS)?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self.compound(path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie,
                    cookieverf,
                    dircount: (self.dir_size / 2).max(1),
                    maxcount: self.dir_size,
                    attr_request: attr_request.clone(),
                }],
            )?)?;
            let (next_cookieverf, batch, eof) = response_readdir(&response)?;
            if let Some(last) = batch.last() {
                cookie = last.cookie;
            } else if !eof {
                return Err(Error::Protocol(
                    "NFSv4 READDIR returned no entries before EOF".into(),
                ));
            }
            cookieverf = next_cookieverf;
            if entries.len().saturating_add(batch.len()) > max_entries {
                return Err(Error::Protocol(format!(
                    "NFSv4 READDIR exceeded configured limit of {max_entries} entries"
                )));
            }
            entries.extend(
                batch
                    .into_iter()
                    .map(DirEntry::from_wire)
                    .collect::<Result<Vec<_>>>()?,
            );
            if eof {
                return Ok(entries);
            }
        }
    }

    /// Sends an empty COMPOUND to keep the session lease fresh.
    pub fn renew(&mut self) -> Result<()> {
        self.compound(Vec::new()).map(|_| ())
    }

    /// Destroys the NFSv4 session.
    ///
    /// Dropping the client closes the TCP connection, but explicit shutdown is
    /// preferred when the server should release session resources promptly.
    pub fn shutdown(mut self) -> Result<()> {
        let response = self.raw_compound(
            "destroy-session",
            self.minor_version,
            vec![Operation::DestroySession(self.session_id)],
        )?;
        response.ensure_ok()
    }

    fn compound(&mut self, operations: Vec<Operation>) -> Result<CompoundResponse> {
        let response = self.compound_status(operations)?;
        response.ensure_ok()?;
        Ok(response)
    }

    fn compound_status(&mut self, operations: Vec<Operation>) -> Result<CompoundResponse> {
        validate_session_compound_operation_count(operations.len(), self.max_operations)?;
        let can_replay_after_session_recovery =
            operations_can_replay_after_session_recovery(&operations);
        let mut retry = 0;
        let mut recovered_session = false;
        loop {
            let mut with_sequence = Vec::with_capacity(operations.len() + 1);
            with_sequence.push(Operation::Sequence(SequenceArgs {
                session_id: self.session_id,
                sequence_id: self.sequence_id,
                slot_id: 0,
                highest_slot_id: 0,
                cache_this: false,
            }));
            with_sequence.extend(operations.iter().cloned());

            let response = self.raw_compound("nfs-rs-v4", self.minor_version, with_sequence)?;
            if sequence_succeeded(&response) {
                self.sequence_id = self.sequence_id.wrapping_add(1).max(1);
            }
            if response_requires_session_recovery(&response) && !recovered_session {
                let err = session_recovery_error(&response);
                self.reconnect()?;
                recovered_session = true;
                if !can_replay_after_session_recovery {
                    return Err(err);
                }
                continue;
            }
            if response_has_retryable_status(&response)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                std::thread::sleep(delay);
                continue;
            }
            return Ok(response);
        }
    }

    fn connect_with_builder(builder: ClientBuilder) -> Result<Self> {
        let mut client = Self::connect_session(builder)?;
        client.refresh_root_fsinfo()?;
        Ok(client)
    }

    fn connect_session(builder: ClientBuilder) -> Result<Self> {
        validate_host(&builder.host)?;
        validate_port("port", builder.port)?;
        validate_owner_id(&builder.owner_id)?;
        validate_open_owner(&builder.open_owner)?;
        validate_transfer_size("read_size", builder.read_size)?;
        validate_transfer_size("write_size", builder.write_size)?;
        validate_transfer_size("dir_size", builder.dir_size)?;
        validate_max_dir_entries(builder.max_dir_entries)?;
        validate_minor_version("max_minor_version", builder.max_minor_version)?;

        let mut last_minor_error = None;
        for minor_version in negotiated_minor_versions(builder.max_minor_version) {
            match Self::connect_session_minor(builder.clone(), minor_version) {
                Ok(client) => return Ok(client),
                Err(err) if is_minor_version_mismatch(&err) => {
                    last_minor_error = Some(err);
                }
                Err(err) => return Err(err),
            }
        }

        Err(last_minor_error.unwrap_or_else(|| {
            Error::Protocol("NFSv4 server did not accept a supported minor version".to_owned())
        }))
    }

    fn connect_session_minor(builder: ClientBuilder, minor_version: u32) -> Result<Self> {
        let stored_builder = builder.clone();
        let mut rpc = RpcClient::connect_with_timeout(
            (builder.host.as_str(), builder.port),
            Auth::sys(builder.auth.clone()),
            builder.timeout,
        )?;
        rpc.set_timeout(builder.timeout)?;
        rpc.set_max_record_size(max_record_size_for_payloads(&[
            builder.read_size,
            builder.write_size,
            builder.dir_size,
        ]));

        let exchange = ExchangeIdArgs {
            client_owner: ClientOwner {
                verifier: builder.client_owner_verifier,
                owner_id: builder.owner_id.clone(),
            },
            flags: EXCHGID4_FLAG_USE_NON_PNFS,
        };

        let exchange_res = raw_compound_with_rpc(
            &mut rpc,
            "exchange-id",
            minor_version,
            vec![Operation::ExchangeId(exchange)],
        )?;
        exchange_res.ensure_ok()?;
        let exchange = response_exchange_id(&exchange_res)?;

        let create_session = CreateSessionArgs {
            client_id: exchange.client_id,
            sequence_id: exchange.sequence_id,
            flags: 0,
            fore_channel_attrs: ChannelAttrs::fore_channel_default(),
            back_channel_attrs: ChannelAttrs::back_channel_disabled(),
            callback_program: 0,
            callback_sec_parms: Vec::new(),
        };
        let session_res = raw_compound_with_rpc(
            &mut rpc,
            "create-session",
            minor_version,
            vec![Operation::CreateSession(create_session)],
        )?;
        session_res.ensure_ok()?;
        let session = response_create_session(&session_res)?;
        let max_operations = session_max_operations(&session.fore_channel_attrs)?;
        let max_request_size = session.fore_channel_attrs.max_request_size;
        let max_response_size = session.fore_channel_attrs.max_response_size;
        validate_session_compound_operation_count(1, max_operations)?;

        let reclaim_res = raw_compound_with_rpc(
            &mut rpc,
            "reclaim-complete",
            minor_version,
            vec![
                Operation::Sequence(SequenceArgs {
                    session_id: session.session_id,
                    sequence_id: 1,
                    slot_id: 0,
                    highest_slot_id: 0,
                    cache_this: false,
                }),
                Operation::ReclaimComplete { one_fs: false },
            ],
        )?;
        ensure_reclaim_complete(&reclaim_res)?;

        let client = Self {
            rpc,
            builder: stored_builder,
            client_id: exchange.client_id,
            session_id: session.session_id,
            sequence_id: 2,
            open_seqid: 1,
            open_owner: builder.open_owner.clone(),
            minor_version,
            max_operations,
            max_request_size,
            max_response_size,
            root_fsinfo: None,
            read_size: builder.read_size,
            write_size: builder.write_size,
            dir_size: builder.dir_size,
            max_dir_entries: builder.max_dir_entries,
            retry_policy: builder.retry_policy,
        };

        Ok(client)
    }

    fn refresh_root_fsinfo(&mut self) -> Result<()> {
        let fsinfo = self.fsinfo("/")?;
        self.apply_fsinfo_limits(&fsinfo);
        self.root_fsinfo = Some(fsinfo);
        Ok(())
    }

    fn apply_fsinfo_limits(&mut self, fsinfo: &FsInfo) {
        let read_limit = self
            .builder
            .read_size
            .min(session_payload_limit(self.max_response_size));
        let write_limit = self
            .builder
            .write_size
            .min(session_payload_limit(self.max_request_size));
        let dir_limit = self
            .builder
            .dir_size
            .min(session_payload_limit(self.max_response_size));

        self.read_size = clamp_io_size(fsinfo.max_read, read_limit);
        self.write_size = clamp_io_size(fsinfo.max_write, write_limit);
        self.dir_size = dir_limit;
        self.rpc.set_max_record_size(max_record_size_for_payloads(&[
            self.read_size,
            self.write_size,
            self.dir_size,
        ]));
    }

    fn raw_compound(
        &mut self,
        tag: impl Into<String>,
        minor_version: u32,
        operations: Vec<Operation>,
    ) -> Result<CompoundResponse> {
        raw_compound_with_rpc(&mut self.rpc, tag, minor_version, operations)
    }
}

#[derive(Debug, Clone)]
struct OpenedFile {
    handle: FileHandle,
    stateid: StateId,
}

impl Client {
    fn open(&mut self, path: &str, share_access: u32, openhow: OpenHow) -> Result<OpenedFile> {
        let (parent_components, file_name) = split_parent(path)?;
        let seqid = self.current_open_seqid();
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Open(OpenArgs {
            seqid,
            share_access: share_access | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
            share_deny: OPEN4_SHARE_DENY_NONE,
            owner: OpenOwner {
                client_id: self.client_id,
                owner: self.open_owner.clone(),
            },
            openhow,
            claim: OpenClaim::Null(file_name),
        }));
        ops.push(Operation::GetFh);

        let response = self.compound_status(ops)?;
        if response_consumed_owner_seqid(&response, OpCode::Open) {
            self.advance_open_seqid();
        }
        response.ensure_ok()?;
        let open = response_open(&response)?;
        let handle = response_getfh(&response)?;
        Ok(OpenedFile {
            handle,
            stateid: open.stateid,
        })
    }

    fn ensure_directory_type(&mut self, path: &str, file_type: Option<FileType>) -> Result<()> {
        let is_directory = match file_type {
            Some(FileType::Directory) => true,
            Some(_) => false,
            None => self.probe_directory(path)?,
        };
        if is_directory {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "{path:?} exists but is not a directory"
            )))
        }
    }

    fn path_is_directory(&mut self, path: &str, file_type: Option<FileType>) -> Result<bool> {
        match file_type {
            Some(FileType::Directory) => Ok(true),
            Some(_) => Ok(false),
            None => match self.metadata(path)?.file_type {
                Some(FileType::Directory) => Ok(true),
                Some(_) => Ok(false),
                None => self.probe_directory(path),
            },
        }
    }

    fn probe_directory(&mut self, path: &str) -> Result<bool> {
        match self.compound(path_ops(
            path,
            vec![Operation::ReadDir {
                cookie: 0,
                cookieverf: [0; NFS4_VERIFIER_SIZE],
                dircount: 1,
                maxcount: self.dir_size.clamp(1, 1024),
                attr_request: Bitmap::empty(),
            }],
        )?) {
            Ok(response) => response_readdir(&response).map(|_| true),
            Err(Error::NfsV4 {
                status: Status::NotDir | Status::BadType | Status::WrongType,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported = self.supported_attrs(path)?;
        Ok(Bitmap::from_supported_attrs(&supported, attrs))
    }

    fn get_supported_attr_values(&mut self, path: &str, attrs: &[u32]) -> Result<Fattr> {
        let attrs = self.supported_attr_request(path, attrs)?;
        if attrs.is_empty() {
            return Ok(Fattr {
                attrmask: attrs,
                attr_vals: Vec::new(),
            });
        }
        let response = self.compound(path_ops(path, vec![Operation::GetAttr(attrs)])?)?;
        response_getattr(&response)
    }

    fn read_opened_at(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<(bool, Vec<u8>)> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::Read {
                stateid: opened.stateid,
                offset,
                count,
            },
        ])?;
        response_read(&response)
    }

    fn seek_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        what: SeekContent,
    ) -> Result<SeekResult> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::Seek {
                stateid: opened.stateid,
                offset,
                what,
            },
        ])?;
        response_seek(&response)
    }

    fn set_opened_size(&mut self, opened: &OpenedFile, size: u64) -> Result<()> {
        self.set_opened_attrs(opened, Fattr::size(size))
    }

    fn set_opened_attrs(&mut self, opened: &OpenedFile, attrs: Fattr) -> Result<()> {
        let setattr_response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::SetAttr {
                stateid: opened.stateid,
                attrs,
            },
        ])?;
        self.ensure_status(setattr_response, "SETATTR")
    }

    fn update_allocation(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
        op: SpaceOp,
    ) -> Result<()> {
        if length == 0 {
            return Ok(());
        }
        require_minor_version(op.name(), self.minor_version, NFS4_MINOR_VERSION_V42)?;

        let opened = self.open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)?;
        let result = self.update_opened_allocation(&opened, offset, length, op);
        let close_result = self.close(opened);
        finish_with_close(result, close_result)
    }

    fn update_opened_allocation(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        length: u64,
        op: SpaceOp,
    ) -> Result<()> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            op.into_operation(opened.stateid, offset, length),
        ])?;
        self.ensure_status(response, op.name())
    }

    fn write_opened_at(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        mut data: &[u8],
    ) -> Result<()> {
        while !data.is_empty() {
            let chunk_len = data.len().min(self.write_size as usize);
            let response = self.compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::Write {
                    stateid: opened.stateid,
                    offset,
                    stable: StableHow::FileSync,
                    data: data[..chunk_len].to_vec(),
                },
            ])?;
            let result = response_write(&response)?;
            let written = result.count;
            if written == 0 {
                return Err(Error::Protocol("NFSv4 WRITE accepted zero bytes".into()));
            }
            let written = written as usize;
            if written > chunk_len {
                return Err(Error::Protocol(format!(
                    "NFSv4 WRITE reported {written} bytes for a {chunk_len} byte request"
                )));
            }
            if !result.committed.satisfies(StableHow::FileSync) {
                let commit = self.commit_opened(opened, offset, result.count)?;
                if commit.verifier != result.verifier {
                    return Err(Error::Protocol(
                        "NFSv4 COMMIT verifier changed after unstable WRITE".into(),
                    ));
                }
            }
            advance_offset(&mut offset, written, "NFSv4 WRITE")?;
            data = &data[written..];
        }
        Ok(())
    }

    fn commit_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<CommitResult> {
        let response = self.compound(vec![
            Operation::PutFh(opened.handle.clone()),
            Operation::Commit { offset, count },
        ])?;
        response_commit(&response)
    }

    fn write_opened_from_reader<R: Read + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_opened_from_reader_at(opened, 0, reader)
    }

    fn write_opened_from_reader_at<R: Read + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        reader: &mut R,
    ) -> Result<u64> {
        let mut written = 0;
        let mut buffer = vec![0; self.write_size as usize];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                return Ok(written);
            }
            self.write_opened_at(opened, offset, &buffer[..read])?;
            advance_offset(&mut offset, read, "NFSv4 WRITE reader")?;
            advance_offset(&mut written, read, "NFSv4 WRITE reader total")?;
        }
    }

    fn copy_opened(&mut self, source: &OpenedFile, target: &OpenedFile) -> Result<u64> {
        let mut offset = 0;
        loop {
            let (eof, data) = self.read_opened_at(source, offset, self.read_size)?;
            if data.len() > self.read_size as usize {
                return Err(Error::Protocol(format!(
                    "NFSv4 READ returned {} bytes for a {} byte request",
                    data.len(),
                    self.read_size
                )));
            }
            if data.is_empty() {
                if eof {
                    return Ok(offset);
                }
                return Err(Error::Protocol(
                    "NFSv4 READ returned no data before EOF".into(),
                ));
            }
            self.write_opened_at(target, offset, &data)?;
            advance_offset(&mut offset, data.len(), "NFSv4 COPY")?;
            if eof {
                return Ok(offset);
            }
        }
    }

    fn close(&mut self, opened: OpenedFile) -> Result<()> {
        let seqid = self.current_open_seqid();
        let response = self.compound_status(vec![
            Operation::PutFh(opened.handle),
            Operation::Close {
                seqid,
                stateid: opened.stateid,
            },
        ])?;
        if response_consumed_owner_seqid(&response, OpCode::Close) {
            self.advance_open_seqid();
        }
        response.ensure_ok()?;
        self.ensure_status(response, "CLOSE")
    }

    fn ensure_status(&self, response: CompoundResponse, operation: &'static str) -> Result<()> {
        self.ensure_status_for(&response, operation)
    }

    fn ensure_status_for(
        &self,
        response: &CompoundResponse,
        operation: &'static str,
    ) -> Result<()> {
        ensure_last_status(response, operation)
    }

    fn current_open_seqid(&self) -> u32 {
        self.open_seqid
    }

    fn advance_open_seqid(&mut self) {
        self.open_seqid = self.open_seqid.wrapping_add(1).max(1);
    }
}

fn raw_compound_with_rpc(
    rpc: &mut RpcClient,
    tag: impl Into<String>,
    minor_version: u32,
    operations: Vec<Operation>,
) -> Result<CompoundResponse> {
    let tag = tag.into();
    let payload = rpc.call(
        NFS4_PROGRAM,
        NFS4_VERSION,
        1,
        &CompoundArgs {
            tag: tag.clone(),
            minor_version,
            operations,
        },
    )?;
    let mut decoder = Decoder::new(&payload);
    let response = CompoundResponse::decode(&mut decoder).map_err(|err| {
        Error::Protocol(format!(
            "failed to decode NFSv4 COMPOUND response for tag {tag:?} at byte {} of {}: {err}",
            decoder.position(),
            payload.len()
        ))
    })?;
    decoder.finish().map_err(|err| {
        Error::Protocol(format!(
            "failed to finish NFSv4 COMPOUND response for tag {tag:?} at byte {} of {}: {err}",
            decoder.position(),
            payload.len()
        ))
    })?;
    Ok(response)
}

fn is_minor_version_mismatch(err: &Error) -> bool {
    matches!(
        err,
        Error::NfsV4 {
            status: Status::MinorVersionMismatch,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_builder_rejects_invalid_transfer_size_before_network() {
        let result = Client::builder("127.0.0.1").read_size(0).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    #[test]
    fn v4_builder_rejects_empty_host_before_network() {
        let result = Client::builder("").connect();
        assert!(matches!(result, Err(Error::InvalidTarget(_))));
    }

    #[test]
    fn v4_builder_rejects_zero_port_before_network() {
        let result = Client::builder("127.0.0.1").port(0).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    #[test]
    fn v4_builder_rejects_invalid_max_dir_entries_before_network() {
        let result = Client::builder("127.0.0.1").max_dir_entries(0).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    #[test]
    fn v4_builder_rejects_invalid_minor_version_before_network() {
        let result = Client::builder("127.0.0.1").max_minor_version(0).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));

        let result = Client::builder("127.0.0.1").max_minor_version(3).connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }

    #[test]
    fn v4_builder_rejects_invalid_open_owner_before_network() {
        let result = Client::builder("127.0.0.1")
            .open_owner(vec![0; NFS4_OPAQUE_LIMIT + 1])
            .connect();
        assert!(matches!(result, Err(Error::Protocol(_))));
    }
}
