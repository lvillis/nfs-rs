#![cfg_attr(not(any(feature = "blocking", feature = "tokio")), allow(dead_code))]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::v4::proto::*;

pub(crate) fn sequence_succeeded(response: &CompoundResponse) -> bool {
    matches!(
        response.results.first(),
        Some(OperationResult::Sequence { status, .. }) if status.is_ok()
    )
}

pub(crate) fn response_has_retryable_status(response: &CompoundResponse) -> bool {
    response.status.is_retryable()
        || response
            .results
            .iter()
            .any(|result| result.status().is_retryable())
}

pub(crate) fn response_requires_session_recovery(response: &CompoundResponse) -> bool {
    matches!(
        response.results.first(),
        Some(OperationResult::Sequence { status, .. }) if status.requires_session_recovery()
    ) || (response.results.is_empty() && response.status.requires_session_recovery())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpaceOp {
    Allocate,
    Deallocate,
}

impl SpaceOp {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Allocate => "ALLOCATE",
            Self::Deallocate => "DEALLOCATE",
        }
    }

    pub(crate) fn into_operation(self, stateid: StateId, offset: u64, length: u64) -> Operation {
        match self {
            Self::Allocate => Operation::Allocate {
                stateid,
                offset,
                length,
            },
            Self::Deallocate => Operation::Deallocate {
                stateid,
                offset,
                length,
            },
        }
    }
}

/// Cursor for paged NFSv4 directory reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirPageCursor {
    /// Cookie of the last entry returned by the previous page.
    pub cookie: u64,
    /// Cookie verifier returned by the server.
    pub cookieverf: Verifier,
}

/// Directory entry returned by high-level NFSv4 directory reads.
///
/// The entry stores parsed basic attributes instead of exposing the raw NFSv4
/// attribute bitmap and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Entry cookie used for pagination.
    pub cookie: u64,
    /// Entry name.
    pub name: String,
    /// Parsed basic attributes returned for the entry.
    pub attributes: BasicAttributes,
}

impl DirEntry {
    pub(crate) fn from_wire(entry: crate::v4::proto::DirEntry) -> Result<Self> {
        Ok(Self {
            cookie: entry.cookie,
            name: entry.name,
            attributes: entry.attrs.parse_basic()?,
        })
    }

    /// Returns the parsed basic attributes for this entry.
    pub fn basic_attributes(&self) -> Result<BasicAttributes> {
        Ok(self.attributes.clone())
    }
}

/// A single page of NFSv4 directory entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirPage {
    /// Entries returned in this page.
    pub entries: Vec<DirEntry>,
    /// Cursor for the next page, or `None` when the server reported EOF.
    pub next_cursor: Option<DirPageCursor>,
}

impl DirPage {
    /// Returns true when there are no further pages to request.
    pub fn is_eof(&self) -> bool {
        self.next_cursor.is_none()
    }
}

pub(crate) fn ensure_last_status(
    response: &CompoundResponse,
    operation: &'static str,
) -> Result<()> {
    if let Some(result) = response.results.last() {
        if result.status().is_ok() {
            return Ok(());
        }
        return Err(Error::nfsv4(operation, result.status()));
    }
    Err(Error::Protocol(format!("{operation} returned no result")))
}

pub(crate) fn finish_with_close<T>(result: Result<T>, close_result: Result<()>) -> Result<T> {
    match result {
        Ok(value) => {
            close_result?;
            Ok(value)
        }
        Err(err) => Err(err),
    }
}

pub(crate) fn advance_offset(
    offset: &mut u64,
    amount: usize,
    operation: &'static str,
) -> Result<()> {
    let amount = u64::try_from(amount).map_err(|_| Error::LengthOutOfRange { len: amount })?;
    *offset = offset
        .checked_add(amount)
        .ok_or_else(|| Error::Protocol(format!("{operation} offset overflow")))?;
    Ok(())
}

pub(crate) fn path_ops(path: &str, tail: Vec<Operation>) -> Result<Vec<Operation>> {
    let mut ops = vec![Operation::PutRootFh];
    for component in path_components(path)? {
        ops.push(Operation::Lookup(component.to_owned()));
    }
    ops.extend(tail);
    Ok(ops)
}

pub(crate) fn path_components(path: &str) -> Result<Vec<&str>> {
    if path.is_empty() {
        return Err(Error::InvalidPath(path.to_owned()));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(Error::InvalidPath(path.to_owned())),
            name if name.len() > NFS4_OPAQUE_LIMIT => {
                return Err(Error::NameTooLong {
                    name: name.to_owned(),
                    max: NFS4_OPAQUE_LIMIT,
                });
            }
            name => components.push(name),
        }
    }
    Ok(components)
}

pub(crate) fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

pub(crate) fn split_parent(path: &str) -> Result<(Vec<&str>, String)> {
    let mut components = path_components(path)?;
    let name = components
        .pop()
        .ok_or_else(|| Error::InvalidPath(path.to_owned()))?
        .to_owned();
    Ok((components, name))
}

pub(crate) fn temporary_sibling_path(path: &str) -> Result<String> {
    let mut components = path_components(path)?;
    components
        .pop()
        .ok_or_else(|| Error::InvalidPath(path.to_owned()))?;

    let mut parent = String::from("/");
    for component in components {
        parent = join_path(&parent, component);
    }

    Ok(join_path(&parent, &temporary_name()))
}

fn temporary_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".nfs-rs-tmp-{}-{nanos}-{counter}", std::process::id())
}

pub(crate) fn response_exchange_id(response: &CompoundResponse) -> Result<ExchangeIdResult> {
    match response.results.first() {
        Some(OperationResult::ExchangeId {
            status,
            result: Some(result),
        }) if status.is_ok() => Ok(result.clone()),
        Some(result) => Err(Error::Protocol(format!(
            "EXCHANGE_ID failed with {:?}",
            result.status()
        ))),
        None => Err(Error::Protocol("EXCHANGE_ID returned no result".into())),
    }
}

pub(crate) fn response_create_session(response: &CompoundResponse) -> Result<CreateSessionResult> {
    match response.results.first() {
        Some(OperationResult::CreateSession {
            status,
            result: Some(result),
        }) if status.is_ok() => Ok(result.clone()),
        Some(result) => Err(Error::Protocol(format!(
            "CREATE_SESSION failed with {:?}",
            result.status()
        ))),
        None => Err(Error::Protocol("CREATE_SESSION returned no result".into())),
    }
}

pub(crate) fn response_open(response: &CompoundResponse) -> Result<OpenResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Open {
                status,
                result: Some(open),
            } if status.is_ok() => Some(Ok(open.clone())),
            OperationResult::Open { status, .. } => Some(Err(Error::nfsv4("OPEN", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include OPEN result".into()))?
}

pub(crate) fn response_getfh(response: &CompoundResponse) -> Result<FileHandle> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::GetFh {
                status,
                handle: Some(handle),
            } if status.is_ok() => Some(Ok(handle.clone())),
            OperationResult::GetFh { status, .. } => Some(Err(Error::nfsv4("GETFH", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include GETFH result".into()))?
}

pub(crate) fn response_getattr(response: &CompoundResponse) -> Result<Fattr> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::GetAttr {
                status,
                attrs: Some(attrs),
            } if status.is_ok() => Some(Ok(attrs.clone())),
            OperationResult::GetAttr { status, .. } => Some(Err(Error::nfsv4("GETATTR", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include GETATTR result".into()))?
}

pub(crate) fn response_access(response: &CompoundResponse) -> Result<AccessResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Access {
                status,
                result: Some(access),
            } if status.is_ok() => Some(Ok(*access)),
            OperationResult::Access { status, .. } => Some(Err(Error::nfsv4("ACCESS", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include ACCESS result".into()))?
}

pub(crate) fn response_read(response: &CompoundResponse) -> Result<(bool, Vec<u8>)> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Read { status, eof, data } if status.is_ok() => {
                Some(Ok((*eof, data.clone())))
            }
            OperationResult::Read { status, .. } => Some(Err(Error::nfsv4("READ", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include READ result".into()))?
}

pub(crate) fn response_readlink(response: &CompoundResponse) -> Result<String> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::ReadLink {
                status,
                data: Some(data),
            } if status.is_ok() => Some(Ok(data.clone())),
            OperationResult::ReadLink { status, .. } => {
                Some(Err(Error::nfsv4("READLINK", *status)))
            }
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include READLINK result".into()))?
}

pub(crate) fn response_write(response: &CompoundResponse) -> Result<WriteResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Write {
                status,
                result: Some(write),
            } if status.is_ok() => Some(Ok(write.clone())),
            OperationResult::Write { status, .. } => Some(Err(Error::nfsv4("WRITE", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include WRITE result".into()))?
}

pub(crate) fn response_commit(response: &CompoundResponse) -> Result<CommitResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Commit {
                status,
                result: Some(commit),
            } if status.is_ok() => Some(Ok(commit.clone())),
            OperationResult::Commit { status, .. } => Some(Err(Error::nfsv4("COMMIT", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include COMMIT result".into()))?
}

pub(crate) fn response_seek(response: &CompoundResponse) -> Result<SeekResult> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::Seek {
                status,
                result: Some(seek),
            } if status.is_ok() => Some(Ok(*seek)),
            OperationResult::Seek { status, .. } => Some(Err(Error::nfsv4("SEEK", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include SEEK result".into()))?
}

pub(crate) fn response_readdir(
    response: &CompoundResponse,
) -> Result<(Verifier, Vec<crate::v4::proto::DirEntry>, bool)> {
    response
        .results
        .iter()
        .find_map(|result| match result {
            OperationResult::ReadDir {
                status,
                cookieverf,
                entries,
                eof,
            } if status.is_ok() => Some(Ok((*cookieverf, entries.clone(), *eof))),
            OperationResult::ReadDir { status, .. } => Some(Err(Error::nfsv4("READDIR", *status))),
            _ => None,
        })
        .ok_or_else(|| Error::Protocol("COMPOUND did not include READDIR result".into()))?
}

pub(crate) fn dir_page_from_entries(
    cookieverf: Verifier,
    entries: Vec<crate::v4::proto::DirEntry>,
    eof: bool,
    max_entries: usize,
) -> Result<DirPage> {
    if entries.len() > max_entries {
        return Err(Error::Protocol(format!(
            "NFSv4 READDIR exceeded configured limit of {max_entries} entries"
        )));
    }
    let next_cursor = if eof {
        None
    } else {
        let last = entries.last().ok_or_else(|| {
            Error::Protocol("NFSv4 READDIR returned no entries before EOF".into())
        })?;
        Some(DirPageCursor {
            cookie: last.cookie,
            cookieverf,
        })
    };
    let entries = entries
        .into_iter()
        .map(DirEntry::from_wire)
        .collect::<Result<Vec<_>>>()?;
    Ok(DirPage {
        entries,
        next_cursor,
    })
}

pub(crate) fn verifier_from_time() -> Verifier {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (duration.as_secs() ^ u64::from(duration.subsec_nanos())).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_components_reject_parent_components() {
        assert!(matches!(
            path_components("../x"),
            Err(Error::InvalidPath(_))
        ));
        assert!(matches!(
            path_components("/safe/../x"),
            Err(Error::InvalidPath(_))
        ));
    }

    #[test]
    fn path_components_reject_oversized_names() {
        let path = "x".repeat(NFS4_OPAQUE_LIMIT + 1);
        assert!(matches!(
            path_components(&path),
            Err(Error::NameTooLong {
                max: NFS4_OPAQUE_LIMIT,
                ..
            })
        ));
    }

    #[test]
    fn joins_remote_paths_without_duplicate_slashes() {
        assert_eq!(join_path("/", "a"), "/a");
        assert_eq!(join_path("/a/", "b"), "/a/b");
        assert_eq!(join_path("a", "b"), "a/b");
    }

    #[test]
    fn builds_temporary_sibling_paths() {
        let path = temporary_sibling_path("/a/b/file.txt").unwrap();
        assert!(path.starts_with("/a/b/.nfs-rs-tmp-"));
        assert!(temporary_sibling_path("/").is_err());
    }

    #[test]
    fn builds_directory_pages_from_entries() {
        let page = dir_page_from_entries(
            [8; NFS4_VERIFIER_SIZE],
            vec![crate::v4::proto::DirEntry {
                cookie: 11,
                name: "file".to_owned(),
                attrs: Fattr::empty(),
            }],
            false,
            16,
        )
        .unwrap();

        assert_eq!(page.entries.len(), 1);
        assert_eq!(
            page.next_cursor,
            Some(DirPageCursor {
                cookie: 11,
                cookieverf: [8; NFS4_VERIFIER_SIZE],
            })
        );
    }

    #[test]
    fn detects_retryable_delay_and_grace_statuses() {
        let response = CompoundResponse {
            status: Status::Delay,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::GetFh,
                status: Status::Delay,
            }],
        };
        assert!(response_has_retryable_status(&response));

        let response = CompoundResponse {
            status: Status::Grace,
            tag: String::new(),
            results: vec![OperationResult::StatusOnly {
                op: OpCode::Open,
                status: Status::Grace,
            }],
        };
        assert!(response_has_retryable_status(&response));
    }

    #[test]
    fn detects_session_recovery_status_only_when_sequence_failed() {
        let failed_sequence = CompoundResponse {
            status: Status::BadSession,
            tag: String::new(),
            results: vec![OperationResult::Sequence {
                status: Status::BadSession,
                result: None,
            }],
        };
        assert!(response_requires_session_recovery(&failed_sequence));

        let failed_later_operation = CompoundResponse {
            status: Status::BadSession,
            tag: String::new(),
            results: vec![
                OperationResult::Sequence {
                    status: Status::Ok,
                    result: Some(SequenceResult {
                        session_id: [1; NFS4_SESSIONID_SIZE],
                        sequence_id: 1,
                        slot_id: 0,
                        highest_slot_id: 0,
                        target_highest_slot_id: 0,
                        status_flags: 0,
                    }),
                },
                OperationResult::StatusOnly {
                    op: OpCode::GetFh,
                    status: Status::BadSession,
                },
            ],
        };
        assert!(!response_requires_session_recovery(&failed_later_operation));

        let empty_compound_failure = CompoundResponse {
            status: Status::DeadSession,
            tag: String::new(),
            results: Vec::new(),
        };
        assert!(response_requires_session_recovery(&empty_compound_failure));
    }

    #[test]
    fn advance_offset_rejects_overflow() {
        let mut offset = u64::MAX;
        assert!(matches!(
            advance_offset(&mut offset, 1, "NFSv4 READ"),
            Err(Error::Protocol(_))
        ));
        assert_eq!(offset, u64::MAX);
    }
}
