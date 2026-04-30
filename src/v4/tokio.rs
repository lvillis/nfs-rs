//! Tokio NFSv4.2 client.
//!
//! This module mirrors the blocking NFSv4.2 client with `async fn` methods and
//! Tokio I/O traits. Paths are absolute paths in the server's v4
//! pseudo-filesystem.
//!
//! ```no_run
//! # async fn run() -> nfs::Result<()> {
//! let mut client = nfs::v4::tokio::Client::connect("127.0.0.1").await?;
//! client.write("/export/object.txt", b"payload").await?;
//! let bytes = client.read("/export/object.txt").await?;
//! assert_eq!(bytes, b"payload");
//! client.shutdown().await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use ::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::retry::RetryPolicy;
use crate::rpc::{Auth, AuthSys, max_record_size_for_payloads};
use crate::tokio_rpc::RpcClient;
use crate::v4::client::{
    SpaceOp, advance_offset, dir_page_from_entries, ensure_last_status, finish_with_close,
    join_path, path_components, path_ops, response_access, response_commit,
    response_create_session, response_exchange_id, response_getattr, response_getfh,
    response_has_retryable_status, response_open, response_read, response_readdir,
    response_readlink, response_requires_session_recovery, response_seek, response_write,
    sequence_succeeded, split_parent, temporary_sibling_path, verifier_from_time,
};
use crate::v4::proto::*;
use crate::v4::{
    clamp_io_size, default_open_owner, default_owner_id, validate_max_dir_entries,
    validate_open_owner, validate_owner_id, validate_transfer_size,
};
use crate::xdr::{Decode, Decoder};

const DEFAULT_IO_SIZE: u32 = 128 * 1024;
const DEFAULT_DIR_SIZE: u32 = 128 * 1024;

pub use crate::v4::client::{DirEntry, DirPage, DirPageCursor};

/// Builder for a Tokio NFSv4.2 [`Client`].
///
/// It has the same configuration model as
/// [`crate::v4::blocking::ClientBuilder`], but connects asynchronously.
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
            retry_policy: RetryPolicy::default(),
        }
    }

    /// Sets AUTH_SYS credentials for RPC calls.
    pub fn auth_sys(mut self, auth: AuthSys) -> Self {
        self.auth = auth;
        self
    }

    /// Sets socket connect/read/write timeout.
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

    /// Sets retry behavior for retryable transport and protocol responses.
    pub fn retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Connects, creates an NFSv4 session, and returns a ready client.
    pub async fn connect(self) -> Result<Client> {
        Client::connect_with_builder(self).await
    }
}

/// Tokio, path-oriented NFSv4.2 client.
///
/// This client owns an asynchronous NFSv4 session and mirrors the high-level
/// operations provided by [`crate::v4::blocking::Client`].
#[derive(Debug)]
pub struct Client {
    rpc: RpcClient,
    builder: ClientBuilder,
    client_id: u64,
    session_id: SessionId,
    sequence_id: u32,
    open_seqid: u32,
    open_owner: Vec<u8>,
    root_fsinfo: Option<FsInfo>,
    read_size: u32,
    write_size: u32,
    dir_size: u32,
    max_dir_entries: usize,
    retry_policy: RetryPolicy,
}

impl Client {
    /// Connects to an NFSv4 server using default builder options.
    pub async fn connect(host: impl Into<String>) -> Result<Self> {
        ClientBuilder::new(host).connect().await
    }

    /// Creates a builder for the given server host.
    pub fn builder(host: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(host)
    }

    /// Resolves a path and returns success if it exists.
    pub async fn lookup(&mut self, path: &str) -> Result<()> {
        self.compound(path_ops(path, Vec::new())?).await.map(|_| ())
    }

    /// Returns whether a path exists.
    pub async fn exists(&mut self, path: &str) -> Result<bool> {
        match self.lookup(path).await {
            Ok(_) => Ok(true),
            Err(Error::NfsV4 {
                status: Status::NoEnt,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Reads basic attributes for a path.
    pub async fn getattr(&mut self, path: &str) -> Result<BasicAttributes> {
        self.get_supported_attr_values(path, FATTR4_BASIC_ATTRS)
            .await?
            .parse_basic()
    }

    /// Alias for [`Client::getattr`].
    pub async fn metadata(&mut self, path: &str) -> Result<BasicAttributes> {
        self.getattr(path).await
    }

    pub async fn file_type(&mut self, path: &str) -> Result<FileType> {
        self.metadata(path).await?.required_file_type()
    }

    pub async fn is_file(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path).await?.is_file())
    }

    pub async fn is_dir(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path).await?.is_dir())
    }

    pub async fn is_symlink(&mut self, path: &str) -> Result<bool> {
        Ok(self.file_type(path).await?.is_symlink())
    }

    pub async fn supported_attrs(&mut self, path: &str) -> Result<Bitmap> {
        let attrs = Bitmap::from_attrs(&[FATTR4_SUPPORTED_ATTRS]);
        let response = self
            .compound(path_ops(path, vec![Operation::GetAttr(attrs)])?)
            .await?;
        response_getattr(&response)?.parse_supported_attrs()
    }

    pub async fn fsstat(&mut self, path: &str) -> Result<FsStat> {
        self.get_supported_attr_values(path, FATTR4_FSSTAT_ATTRS)
            .await?
            .parse_fsstat()
    }

    pub async fn fsinfo(&mut self, path: &str) -> Result<FsInfo> {
        self.get_supported_attr_values(path, FATTR4_FSINFO_ATTRS)
            .await?
            .parse_fsinfo()
    }

    pub async fn pathconf(&mut self, path: &str) -> Result<PathConf> {
        self.get_supported_attr_values(path, FATTR4_PATHCONF_ATTRS)
            .await?
            .parse_pathconf()
    }

    pub fn root_fsinfo(&self) -> Option<&FsInfo> {
        self.root_fsinfo.as_ref()
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        let previous_client_id = self.client_id;
        let previous_open_seqid = self.open_seqid;
        let previous_root_fsinfo = self.root_fsinfo.clone();
        let previous_read_size = self.read_size;
        let previous_write_size = self.write_size;
        let previous_dir_size = self.dir_size;

        let mut rebuilt = Self::connect_session(self.builder.clone()).await?;
        if rebuilt.client_id == previous_client_id {
            rebuilt.open_seqid = previous_open_seqid;
        }
        rebuilt.root_fsinfo = previous_root_fsinfo;
        rebuilt.read_size = previous_read_size;
        rebuilt.write_size = previous_write_size;
        rebuilt.dir_size = previous_dir_size;
        rebuilt
            .rpc
            .set_max_record_size(max_record_size_for_payloads(&[
                rebuilt.read_size,
                rebuilt.write_size,
                rebuilt.dir_size,
            ]));
        *self = rebuilt;
        Ok(())
    }

    pub async fn access(&mut self, path: &str, access: u32) -> Result<AccessResult> {
        let response = self
            .compound(path_ops(path, vec![Operation::Access(access)])?)
            .await?;
        response_access(&response)
    }

    pub async fn read(&mut self, path: &str) -> Result<Vec<u8>> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_opened_to_end(&opened).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        path: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_opened_to_writer(&opened, writer).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_range_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        path: &str,
        offset: u64,
        count: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self
            .read_opened_range_to_writer(&opened, offset, count, writer)
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_range(&mut self, path: &str, offset: u64, count: u64) -> Result<Vec<u8>> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_opened_range_vec(&opened, offset, count).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.read_opened_range(&opened, offset, count).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn read_exact_at(&mut self, path: &str, offset: u64, count: u32) -> Result<Vec<u8>> {
        let data = self.read_at(path, offset, count).await?;
        if data.len() != count as usize {
            return Err(Error::Protocol(format!(
                "NFSv4 READ returned {} bytes before EOF; expected {count}",
                data.len()
            )));
        }
        Ok(data)
    }

    pub async fn seek(&mut self, path: &str, offset: u64, what: SeekContent) -> Result<SeekResult> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let result = self.seek_opened(&opened, offset, what).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn seek_data(&mut self, path: &str, offset: u64) -> Result<Option<u64>> {
        self.seek(path, offset, SeekContent::Data)
            .await
            .map(SeekResult::found_offset)
    }

    pub async fn seek_hole(&mut self, path: &str, offset: u64) -> Result<Option<u64>> {
        self.seek(path, offset, SeekContent::Hole)
            .await
            .map(SeekResult::found_offset)
    }

    pub async fn read_link(&mut self, path: &str) -> Result<String> {
        let response = self
            .compound(path_ops(path, vec![Operation::ReadLink])?)
            .await?;
        response_readlink(&response)
    }

    async fn read_opened_to_end(&mut self, opened: &OpenedFile) -> Result<Vec<u8>> {
        let mut offset = 0;
        let mut out = Vec::new();
        loop {
            let (eof, data) = self.read_opened_at(opened, offset, self.read_size).await?;
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

    async fn read_opened_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        writer: &mut W,
    ) -> Result<u64> {
        let mut offset = 0;
        let mut total = 0;
        loop {
            let (eof, data) = self.read_opened_at(opened, offset, self.read_size).await?;
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
            writer.write_all(&data).await?;
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            advance_offset(&mut total, data.len(), "NFSv4 READ total")?;
            if eof {
                return Ok(total);
            }
        }
    }

    async fn read_opened_range(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>> {
        self.read_opened_range_vec(opened, offset, u64::from(count))
            .await
    }

    async fn read_opened_range_vec(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u64,
    ) -> Result<Vec<u8>> {
        let capacity = usize::try_from(count).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(capacity.min(self.read_size as usize));
        self.read_opened_range_to_writer(opened, offset, count, &mut out)
            .await?;
        Ok(out)
    }

    async fn read_opened_range_to_writer<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        mut remaining: u64,
        writer: &mut W,
    ) -> Result<u64> {
        let mut total = 0;
        while remaining > 0 {
            let request = u64::from(self.read_size).min(remaining) as u32;
            let (eof, data) = self.read_opened_at(opened, offset, request).await?;
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
            writer.write_all(&data).await?;
            advance_offset(&mut offset, data.len(), "NFSv4 READ")?;
            advance_offset(&mut total, data.len(), "NFSv4 READ total")?;
            remaining -= data.len() as u64;
            if eof {
                return Ok(total);
            }
        }
        Ok(total)
    }

    pub async fn write(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_with_mode(path, data, 0o644).await
    }

    pub async fn write_with_mode(&mut self, path: &str, data: &[u8], mode: u32) -> Result<()> {
        let opened = self
            .open(
                path,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
            )
            .await?;
        let result = match self.set_opened_size(&opened, 0).await {
            Ok(()) => self.write_opened_at(&opened, 0, data).await,
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn write_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_from_reader_with_mode(path, reader, 0o644).await
    }

    pub async fn write_from_reader_with_mode<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let opened = self
            .open(
                path,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
            )
            .await?;
        let result = match self.set_opened_size(&opened, 0).await {
            Ok(()) => self.write_opened_from_reader(&opened, reader).await,
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn write_atomic(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.write_atomic_with_mode(path, data, 0o644).await
    }

    pub async fn write_atomic_with_mode(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<()> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self
            .open(
                &temp,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
            )
            .await
        {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_at(&opened, 0, data).await;
                let close_result = self.close(opened).await;
                match finish_with_close(write_result, close_result) {
                    Ok(()) => self.rename(&temp, path).await,
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };

        if result.is_err() && created {
            let _ = self.remove(&temp).await;
        }
        result
    }

    pub async fn write_atomic_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_atomic_from_reader_with_mode(path, reader, 0o644)
            .await
    }

    pub async fn write_atomic_from_reader_with_mode<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
        mode: u32,
    ) -> Result<u64> {
        let temp = temporary_sibling_path(path)?;
        let mut created = false;

        let result = match self
            .open(
                &temp,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
            )
            .await
        {
            Ok(opened) => {
                created = true;
                let write_result = self.write_opened_from_reader(&opened, reader).await;
                let close_result = self.close(opened).await;
                match finish_with_close(write_result, close_result) {
                    Ok(written) => match self.rename(&temp, path).await {
                        Ok(()) => Ok(written),
                        Err(err) => Err(err),
                    },
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };

        if result.is_err() && created {
            let _ = self.remove(&temp).await;
        }
        result
    }

    pub async fn append(&mut self, path: &str, data: &[u8]) -> Result<u64> {
        let offset = self.metadata(path).await?.size.ok_or_else(|| {
            Error::Protocol("NFSv4 size attribute is required for append".to_owned())
        })?;
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = match self.write_opened_at(&opened, offset, data).await {
            Ok(()) => {
                let mut written = 0;
                advance_offset(&mut written, data.len(), "NFSv4 APPEND").map(|()| written)
            }
            Err(err) => Err(err),
        };
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn append_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        let offset = self.metadata(path).await?.size.ok_or_else(|| {
            Error::Protocol("NFSv4 size attribute is required for append".to_owned())
        })?;
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self
            .write_opened_from_reader_at(&opened, offset, reader)
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self.set_opened_size(&opened, size).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn allocate(&mut self, path: &str, offset: u64, length: u64) -> Result<()> {
        self.update_allocation(path, offset, length, SpaceOp::Allocate)
            .await
    }

    pub async fn deallocate(&mut self, path: &str, offset: u64, length: u64) -> Result<()> {
        self.update_allocation(path, offset, length, SpaceOp::Deallocate)
            .await
    }

    pub async fn setattr(&mut self, path: &str, attrs: &SetAttrs) -> Result<()> {
        let attrs = Fattr::from_set_attrs(attrs)?;
        if attrs.attrmask.is_empty() {
            return Ok(());
        }
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::SetAttr {
                    stateid: StateId::anonymous(),
                    attrs,
                }],
            )?)
            .await?;
        self.ensure_status(response, "SETATTR")
    }

    pub async fn set_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.setattr(path, &SetAttrs::mode(mode)).await
    }

    pub async fn set_owner(&mut self, path: &str, owner: impl Into<String>) -> Result<()> {
        self.setattr(path, &SetAttrs::owner(owner)).await
    }

    pub async fn set_owner_group(
        &mut self,
        path: &str,
        owner_group: impl Into<String>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::owner_group(owner_group))
            .await
    }

    pub async fn set_ownership(
        &mut self,
        path: &str,
        owner: impl Into<String>,
        owner_group: impl Into<String>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::ownership(owner, owner_group))
            .await
    }

    pub async fn set_times(
        &mut self,
        path: &str,
        access_time: Option<NfsTime>,
        modify_time: Option<NfsTime>,
    ) -> Result<()> {
        self.setattr(path, &SetAttrs::times(access_time, modify_time))
            .await
    }

    pub async fn touch(&mut self, path: &str) -> Result<()> {
        self.setattr(path, &SetAttrs::touch()).await
    }

    pub async fn write_at(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<()> {
        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self.write_opened_at(&opened, offset, data).await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    pub async fn copy(&mut self, from: &str, to: &str) -> Result<u64> {
        if path_components(from)? == path_components(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let mode = self.metadata(from).await?.mode.unwrap_or(0o644) & 0o7777;
        let source = self
            .open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let target = match self
            .open(
                to,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Unchecked(Fattr::mode(mode)),
            )
            .await
        {
            Ok(target) => target,
            Err(err) => {
                let _ = self.close(source).await;
                return Err(err);
            }
        };

        let result = match self.set_opened_size(&target, 0).await {
            Ok(()) => self.copy_opened(&source, &target).await,
            Err(err) => Err(err),
        };
        let target_close = self.close(target).await;
        let source_close = self.close(source).await;
        match result {
            Ok(copied) => {
                target_close?;
                source_close?;
                Ok(copied)
            }
            Err(err) => Err(err),
        }
    }

    pub async fn copy_atomic(&mut self, from: &str, to: &str) -> Result<u64> {
        if path_components(from)? == path_components(to)? {
            return Err(Error::Protocol(
                "copy source and destination must differ".to_owned(),
            ));
        }
        let mode = self.metadata(from).await?.mode.unwrap_or(0o644) & 0o7777;
        let temp = temporary_sibling_path(to)?;
        let source = self
            .open(from, OPEN4_SHARE_ACCESS_READ, OpenHow::NoCreate)
            .await?;
        let target = match self
            .open(
                &temp,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
            )
            .await
        {
            Ok(target) => target,
            Err(err) => {
                let _ = self.close(source).await;
                return Err(err);
            }
        };

        let copy_result = self.copy_opened(&source, &target).await;
        let target_close = self.close(target).await;
        let source_close = self.close(source).await;
        let result = match copy_result {
            Ok(copied) => {
                target_close?;
                source_close?;
                match self.rename(&temp, to).await {
                    Ok(()) => Ok(copied),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        };

        if result.is_err() {
            let _ = self.remove(&temp).await;
        }
        result
    }

    pub async fn commit(&mut self, path: &str, offset: u64, count: u32) -> Result<CommitResult> {
        let response = self
            .compound(path_ops(path, vec![Operation::Commit { offset, count }])?)
            .await?;
        response_commit(&response)
    }

    pub async fn create(&mut self, path: &str) -> Result<()> {
        self.create_new(path).await
    }

    pub async fn create_new(&mut self, path: &str) -> Result<()> {
        self.create_new_with_mode(path, 0o644).await
    }

    pub async fn create_with_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        self.create_new_with_mode(path, mode).await
    }

    pub async fn create_new_with_mode(&mut self, path: &str, mode: u32) -> Result<()> {
        let opened = self
            .open(
                path,
                OPEN4_SHARE_ACCESS_BOTH,
                OpenHow::Guarded(Fattr::mode(mode)),
            )
            .await?;
        self.close(opened).await
    }

    pub async fn mkdir(&mut self, path: &str, mode: u32) -> Result<()> {
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

        let response = self.compound(ops).await?;
        self.ensure_status_for(&response, "CREATE")
    }

    pub async fn create_dir_all(&mut self, path: &str, mode: u32) -> Result<()> {
        let components = path_components(path)?;
        let mut current = String::from("/");
        for component in components {
            current = join_path(&current, component);
            match self.metadata(&current).await {
                Ok(attrs) => {
                    self.ensure_directory_type(&current, attrs.file_type)
                        .await?
                }
                Err(Error::NfsV4 {
                    status: Status::NoEnt,
                    ..
                }) => match self.mkdir(&current, mode).await {
                    Ok(_) => {}
                    Err(Error::NfsV4 {
                        status: Status::Exist,
                        ..
                    }) => {
                        let attrs = self.metadata(&current).await?;
                        self.ensure_directory_type(&current, attrs.file_type)
                            .await?;
                    }
                    Err(err) => return Err(err),
                },
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub async fn symlink(&mut self, path: &str, target: &str) -> Result<()> {
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

        let response = self.compound(ops).await?;
        self.ensure_status_for(&response, "CREATE")
    }

    pub async fn hard_link(&mut self, existing: &str, link: &str) -> Result<()> {
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

        let response = self.compound(ops).await?;
        self.ensure_status(response, "LINK")
    }

    pub async fn remove(&mut self, path: &str) -> Result<()> {
        let (parent_components, name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Remove(name));

        let response = self.compound(ops).await?;
        self.ensure_status(response, "REMOVE")
    }

    pub async fn remove_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove(path).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn rmdir(&mut self, path: &str) -> Result<()> {
        self.remove(path).await
    }

    pub async fn rmdir_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.rmdir(path).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn remove_all(&mut self, path: &str) -> Result<()> {
        if path_components(path)?.is_empty() {
            return Err(Error::InvalidPath(path.to_owned()));
        }

        enum RemoveTask {
            Visit(String, Option<FileType>),
            RemoveDir(String),
        }

        let file_type = self.metadata(path).await?.file_type;
        let mut stack = vec![RemoveTask::Visit(path.to_owned(), file_type)];
        while let Some(task) = stack.pop() {
            match task {
                RemoveTask::Visit(path, file_type) => {
                    if self.path_is_directory(&path, file_type).await? {
                        stack.push(RemoveTask::RemoveDir(path.clone()));
                        let entries = self.read_dir(&path).await?;
                        for entry in entries.into_iter().rev() {
                            if entry.name == "." || entry.name == ".." {
                                continue;
                            }
                            let child = join_path(&path, &entry.name);
                            let child_type = entry.basic_attributes()?.file_type;
                            stack.push(RemoveTask::Visit(child, child_type));
                        }
                    } else {
                        self.remove(&path).await?;
                    }
                }
                RemoveTask::RemoveDir(path) => self.rmdir(&path).await?,
            }
        }

        Ok(())
    }

    pub async fn remove_all_if_exists(&mut self, path: &str) -> Result<bool> {
        match self.remove_all(path).await {
            Ok(()) => Ok(true),
            Err(err) if err.is_not_found() => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
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

        let response = self.compound(ops).await?;
        self.ensure_status(response, "RENAME")
    }

    pub async fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.read_dir_with_limit(path, self.max_dir_entries).await
    }

    pub async fn read_dir_limited(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        validate_max_dir_entries(max_entries)?;
        self.read_dir_with_limit(path, max_entries.min(self.max_dir_entries))
            .await
    }

    pub async fn read_dir_page(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
    ) -> Result<DirPage> {
        self.read_dir_page_limited(path, cursor, self.max_dir_entries)
            .await
    }

    pub async fn read_dir_page_limited(
        &mut self,
        path: &str,
        cursor: Option<DirPageCursor>,
        max_entries: usize,
    ) -> Result<DirPage> {
        validate_max_dir_entries(max_entries)?;
        let max_entries = max_entries.min(self.max_dir_entries);
        let attr_request = self
            .supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let cursor = cursor.unwrap_or_default();
        let response = self
            .compound(path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie: cursor.cookie,
                    cookieverf: cursor.cookieverf,
                    dircount: (self.dir_size / 2).max(1),
                    maxcount: self.dir_size,
                    attr_request,
                }],
            )?)
            .await?;
        let (cookieverf, entries, eof) = response_readdir(&response)?;
        dir_page_from_entries(cookieverf, entries, eof, max_entries)
    }

    async fn read_dir_with_limit(
        &mut self,
        path: &str,
        max_entries: usize,
    ) -> Result<Vec<DirEntry>> {
        let attr_request = self
            .supported_attr_request(path, FATTR4_BASIC_ATTRS)
            .await?;
        let mut cookie = 0;
        let mut cookieverf = [0; NFS4_VERIFIER_SIZE];
        let mut entries = Vec::new();
        loop {
            let response = self
                .compound(path_ops(
                    path,
                    vec![Operation::ReadDir {
                        cookie,
                        cookieverf,
                        dircount: (self.dir_size / 2).max(1),
                        maxcount: self.dir_size,
                        attr_request: attr_request.clone(),
                    }],
                )?)
                .await?;
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

    pub async fn renew(&mut self) -> Result<()> {
        self.compound(Vec::new()).await.map(|_| ())
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let session_id = self.session_id;
        let response = self
            .raw_compound(
                "destroy-session",
                NFS4_MINOR_VERSION_LATEST,
                vec![Operation::DestroySession(session_id)],
            )
            .await?;
        response.ensure_ok()
    }

    async fn compound(&mut self, operations: Vec<Operation>) -> Result<CompoundResponse> {
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

            let response = self
                .raw_compound("nfs-rs-v4", NFS4_MINOR_VERSION_LATEST, with_sequence)
                .await?;
            if sequence_succeeded(&response) {
                self.sequence_id = self.sequence_id.wrapping_add(1).max(1);
            }
            if response_requires_session_recovery(&response) && !recovered_session {
                self.reconnect().await?;
                recovered_session = true;
                continue;
            }
            if response_has_retryable_status(&response)
                && let Some(delay) = self.retry_policy.delay_for_retry(retry)
            {
                retry += 1;
                ::tokio::time::sleep(delay).await;
                continue;
            }
            response.ensure_ok()?;
            return Ok(response);
        }
    }

    async fn connect_with_builder(builder: ClientBuilder) -> Result<Self> {
        let mut client = Self::connect_session(builder).await?;
        client.refresh_root_fsinfo().await?;
        Ok(client)
    }

    async fn connect_session(builder: ClientBuilder) -> Result<Self> {
        validate_owner_id(&builder.owner_id)?;
        validate_open_owner(&builder.open_owner)?;
        validate_transfer_size("read_size", builder.read_size)?;
        validate_transfer_size("write_size", builder.write_size)?;
        validate_transfer_size("dir_size", builder.dir_size)?;
        validate_max_dir_entries(builder.max_dir_entries)?;

        let stored_builder = builder.clone();
        let mut rpc = RpcClient::connect_with_timeout(
            (builder.host.as_str(), builder.port),
            Auth::sys(builder.auth.clone()),
            builder.timeout,
        )
        .await?;
        rpc.set_timeout(builder.timeout);
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
            flags: 0x0001_0000,
        };
        let exchange_res = raw_compound_with_rpc(
            &mut rpc,
            "exchange-id",
            NFS4_MINOR_VERSION_LATEST,
            vec![Operation::ExchangeId(exchange)],
        )
        .await?;
        exchange_res.ensure_ok()?;
        let exchange = response_exchange_id(&exchange_res)?;

        let create_session = CreateSessionArgs {
            client_id: exchange.client_id,
            sequence_id: exchange.sequence_id,
            flags: 0,
            fore_channel_attrs: ChannelAttrs::fore_channel_default(),
            back_channel_attrs: ChannelAttrs::back_channel_disabled(),
            callback_program: 0,
        };
        let session_res = raw_compound_with_rpc(
            &mut rpc,
            "create-session",
            NFS4_MINOR_VERSION_LATEST,
            vec![Operation::CreateSession(create_session)],
        )
        .await?;
        session_res.ensure_ok()?;
        let session = response_create_session(&session_res)?;

        let reclaim_res = raw_compound_with_rpc(
            &mut rpc,
            "reclaim-complete",
            NFS4_MINOR_VERSION_LATEST,
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
        )
        .await?;
        reclaim_res.ensure_ok()?;

        let client = Self {
            rpc,
            builder: stored_builder,
            client_id: exchange.client_id,
            session_id: session.session_id,
            sequence_id: 2,
            open_seqid: 1,
            open_owner: builder.open_owner.clone(),
            root_fsinfo: None,
            read_size: builder.read_size,
            write_size: builder.write_size,
            dir_size: builder.dir_size,
            max_dir_entries: builder.max_dir_entries,
            retry_policy: builder.retry_policy,
        };

        Ok(client)
    }

    async fn refresh_root_fsinfo(&mut self) -> Result<()> {
        self.root_fsinfo = Some(self.fsinfo("/").await?);
        if let Some(fsinfo) = &self.root_fsinfo {
            self.read_size = clamp_io_size(fsinfo.max_read, self.builder.read_size);
            self.write_size = clamp_io_size(fsinfo.max_write, self.builder.write_size);
            self.rpc.set_max_record_size(max_record_size_for_payloads(&[
                self.read_size,
                self.write_size,
                self.dir_size,
            ]));
        }
        Ok(())
    }

    async fn raw_compound(
        &mut self,
        tag: impl Into<String>,
        minor_version: u32,
        operations: Vec<Operation>,
    ) -> Result<CompoundResponse> {
        raw_compound_with_rpc(&mut self.rpc, tag, minor_version, operations).await
    }
}

#[derive(Debug, Clone)]
struct OpenedFile {
    handle: FileHandle,
    stateid: StateId,
}

impl Client {
    async fn open(
        &mut self,
        path: &str,
        share_access: u32,
        openhow: OpenHow,
    ) -> Result<OpenedFile> {
        let (parent_components, file_name) = split_parent(path)?;
        let mut ops = vec![Operation::PutRootFh];
        for component in parent_components {
            ops.push(Operation::Lookup(component.to_owned()));
        }
        ops.push(Operation::Open(OpenArgs {
            seqid: self.next_open_seqid(),
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

        let response = self.compound(ops).await?;
        let open = response_open(&response)?;
        let handle = response_getfh(&response)?;
        Ok(OpenedFile {
            handle,
            stateid: open.stateid,
        })
    }

    async fn ensure_directory_type(
        &mut self,
        path: &str,
        file_type: Option<FileType>,
    ) -> Result<()> {
        let is_directory = match file_type {
            Some(FileType::Directory) => true,
            Some(_) => false,
            None => self.probe_directory(path).await?,
        };
        if is_directory {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "{path:?} exists but is not a directory"
            )))
        }
    }

    async fn path_is_directory(&mut self, path: &str, file_type: Option<FileType>) -> Result<bool> {
        match file_type {
            Some(FileType::Directory) => Ok(true),
            Some(_) => Ok(false),
            None => match self.metadata(path).await?.file_type {
                Some(FileType::Directory) => Ok(true),
                Some(_) => Ok(false),
                None => self.probe_directory(path).await,
            },
        }
    }

    async fn probe_directory(&mut self, path: &str) -> Result<bool> {
        match self
            .compound(path_ops(
                path,
                vec![Operation::ReadDir {
                    cookie: 0,
                    cookieverf: [0; NFS4_VERIFIER_SIZE],
                    dircount: 1,
                    maxcount: self.dir_size.clamp(1, 1024),
                    attr_request: Bitmap::empty(),
                }],
            )?)
            .await
        {
            Ok(response) => response_readdir(&response).map(|_| true),
            Err(Error::NfsV4 {
                status: Status::NotDir | Status::BadType | Status::WrongType,
                ..
            }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    async fn supported_attr_request(&mut self, path: &str, attrs: &[u32]) -> Result<Bitmap> {
        let supported = self.supported_attrs(path).await?;
        Ok(Bitmap::from_supported_attrs(&supported, attrs))
    }

    async fn get_supported_attr_values(&mut self, path: &str, attrs: &[u32]) -> Result<Fattr> {
        let attrs = self.supported_attr_request(path, attrs).await?;
        if attrs.is_empty() {
            return Ok(Fattr {
                attrmask: attrs,
                attr_vals: Vec::new(),
            });
        }
        let response = self
            .compound(path_ops(path, vec![Operation::GetAttr(attrs)])?)
            .await?;
        response_getattr(&response)
    }

    async fn read_opened_at(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        count: u32,
    ) -> Result<(bool, Vec<u8>)> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::Read {
                    stateid: opened.stateid,
                    offset,
                    count,
                },
            ])
            .await?;
        response_read(&response)
    }

    async fn seek_opened(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        what: SeekContent,
    ) -> Result<SeekResult> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::Seek {
                    stateid: opened.stateid,
                    offset,
                    what,
                },
            ])
            .await?;
        response_seek(&response)
    }

    async fn set_opened_size(&mut self, opened: &OpenedFile, size: u64) -> Result<()> {
        let setattr_response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                Operation::SetAttr {
                    stateid: opened.stateid,
                    attrs: Fattr::size(size),
                },
            ])
            .await?;
        self.ensure_status(setattr_response, "SETATTR")
    }

    async fn update_allocation(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
        op: SpaceOp,
    ) -> Result<()> {
        if length == 0 {
            return Ok(());
        }

        let opened = self
            .open(path, OPEN4_SHARE_ACCESS_WRITE, OpenHow::NoCreate)
            .await?;
        let result = self
            .update_opened_allocation(&opened, offset, length, op)
            .await;
        let close_result = self.close(opened).await;
        finish_with_close(result, close_result)
    }

    async fn update_opened_allocation(
        &mut self,
        opened: &OpenedFile,
        offset: u64,
        length: u64,
        op: SpaceOp,
    ) -> Result<()> {
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle.clone()),
                op.into_operation(opened.stateid, offset, length),
            ])
            .await?;
        self.ensure_status(response, op.name())
    }

    async fn write_opened_at(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        mut data: &[u8],
    ) -> Result<()> {
        while !data.is_empty() {
            let chunk_len = data.len().min(self.write_size as usize);
            let response = self
                .compound(vec![
                    Operation::PutFh(opened.handle.clone()),
                    Operation::Write {
                        stateid: opened.stateid,
                        offset,
                        stable: StableHow::FileSync,
                        data: data[..chunk_len].to_vec(),
                    },
                ])
                .await?;
            let written = response_write(&response)?.count;
            if written == 0 {
                return Err(Error::Protocol("NFSv4 WRITE accepted zero bytes".into()));
            }
            let written = written as usize;
            if written > chunk_len {
                return Err(Error::Protocol(format!(
                    "NFSv4 WRITE reported {written} bytes for a {chunk_len} byte request"
                )));
            }
            advance_offset(&mut offset, written, "NFSv4 WRITE")?;
            data = &data[written..];
        }
        Ok(())
    }

    async fn write_opened_from_reader<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        reader: &mut R,
    ) -> Result<u64> {
        self.write_opened_from_reader_at(opened, 0, reader).await
    }

    async fn write_opened_from_reader_at<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        opened: &OpenedFile,
        mut offset: u64,
        reader: &mut R,
    ) -> Result<u64> {
        let mut written = 0;
        let mut buffer = vec![0; self.write_size as usize];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 {
                return Ok(written);
            }
            self.write_opened_at(opened, offset, &buffer[..read])
                .await?;
            advance_offset(&mut offset, read, "NFSv4 WRITE reader")?;
            advance_offset(&mut written, read, "NFSv4 WRITE reader total")?;
        }
    }

    async fn copy_opened(&mut self, source: &OpenedFile, target: &OpenedFile) -> Result<u64> {
        let mut offset = 0;
        loop {
            let (eof, data) = self.read_opened_at(source, offset, self.read_size).await?;
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
            self.write_opened_at(target, offset, &data).await?;
            advance_offset(&mut offset, data.len(), "NFSv4 COPY")?;
            if eof {
                return Ok(offset);
            }
        }
    }

    async fn close(&mut self, opened: OpenedFile) -> Result<()> {
        let seqid = self.next_open_seqid();
        let response = self
            .compound(vec![
                Operation::PutFh(opened.handle),
                Operation::Close {
                    seqid,
                    stateid: opened.stateid,
                },
            ])
            .await?;
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

    fn next_open_seqid(&mut self) -> u32 {
        let seqid = self.open_seqid;
        self.open_seqid = self.open_seqid.wrapping_add(1).max(1);
        seqid
    }
}

async fn raw_compound_with_rpc(
    rpc: &mut RpcClient,
    tag: impl Into<String>,
    minor_version: u32,
    operations: Vec<Operation>,
) -> Result<CompoundResponse> {
    let tag = tag.into();
    let payload = rpc
        .call(
            NFS4_PROGRAM,
            NFS4_VERSION,
            1,
            &CompoundArgs {
                tag: tag.clone(),
                minor_version,
                operations,
            },
        )
        .await?;
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
