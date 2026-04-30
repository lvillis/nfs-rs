#![cfg(feature = "protocol")]

use nfs::Error;
use nfs::v4::protocol::{
    ACCESS4_LOOKUP, ACCESS4_READ, Bitmap, CompoundArgs, CompoundResponse, CreateArgs, CreateKind,
    FATTR4_BASIC_ATTRS, FATTR4_CASE_INSENSITIVE, FATTR4_CASE_PRESERVING, FATTR4_CHANGE,
    FATTR4_CHOWN_RESTRICTED, FATTR4_FH_EXPIRE_TYPE, FATTR4_FILEID, FATTR4_FILES_AVAIL,
    FATTR4_FILES_FREE, FATTR4_FILES_TOTAL, FATTR4_FSINFO_ATTRS, FATTR4_FSSTAT_ATTRS,
    FATTR4_HOMOGENEOUS, FATTR4_LEASE_TIME, FATTR4_LINK_SUPPORT, FATTR4_MAXFILESIZE, FATTR4_MAXLINK,
    FATTR4_MAXNAME, FATTR4_MAXREAD, FATTR4_MAXWRITE, FATTR4_MODE, FATTR4_NO_TRUNC, FATTR4_NUMLINKS,
    FATTR4_OWNER, FATTR4_OWNER_GROUP, FATTR4_PATHCONF_ATTRS, FATTR4_SIZE, FATTR4_SPACE_AVAIL,
    FATTR4_SPACE_FREE, FATTR4_SPACE_TOTAL, FATTR4_SPACE_USED, FATTR4_SUPPORTED_ATTRS,
    FATTR4_SYMLINK_SUPPORT, FATTR4_TIME_ACCESS, FATTR4_TIME_ACCESS_SET, FATTR4_TIME_DELTA,
    FATTR4_TIME_METADATA, FATTR4_TIME_MODIFY, FATTR4_TIME_MODIFY_SET, FATTR4_TYPE,
    FATTR4_UNIQUE_HANDLES, Fattr, FileHandle, FileType, NFS4_MINOR_VERSION_LATEST, NfsTime,
    OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_ACCESS_WANT_NO_DELEG, OPEN4_SHARE_DENY_NONE, OpCode,
    OpenArgs, OpenClaim, OpenHow, OpenOwner, Operation, OperationResult, SeekContent, SeekResult,
    SetAttrs, SetTime, StableHow, StateId, Status,
};
use nfs::xdr::{Decode, Decoder, Encode, Encoder, to_bytes};

#[test]
fn encodes_compound_with_v42_minor_version() {
    let args = CompoundArgs {
        tag: "t".to_owned(),
        minor_version: NFS4_MINOR_VERSION_LATEST,
        operations: vec![Operation::PutRootFh, Operation::GetFh],
    };

    assert_eq!(
        to_bytes(&args).unwrap(),
        vec![
            0, 0, 0, 1, b't', 0, 0, 0, // tag
            0, 0, 0, 2, // minor version
            0, 0, 0, 2, // op count
            0, 0, 0, 24, // OP_PUTROOTFH
            0, 0, 0, 10, // OP_GETFH
        ]
    );
}

#[test]
fn decodes_getfh_compound_response() {
    let wire = vec![
        0, 0, 0, 0, // compound status
        0, 0, 0, 1, b't', 0, 0, 0, // tag
        0, 0, 0, 2, // result count
        0, 0, 0, 24, 0, 0, 0, 0, // PUTROOTFH status
        0, 0, 0, 10, 0, 0, 0, 0, // GETFH status
        0, 0, 0, 3, 1, 2, 3, 0, // filehandle
    ];

    let mut decoder = Decoder::new(&wire);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert_eq!(response.results.len(), 2);
    assert!(matches!(
        &response.results[1],
        OperationResult::GetFh {
            handle: Some(handle),
            ..
        } if handle.as_bytes() == [1, 2, 3]
    ));
}

#[test]
fn decodes_readdir_entries_with_basic_attributes() {
    let mut attr_vals = Encoder::new();
    attr_vals.write_u32(1); // NF4REG
    attr_vals.write_u64(512);
    let attrs = Fattr {
        attrmask: Bitmap::from_attrs(&[FATTR4_TYPE, FATTR4_SIZE]),
        attr_vals: attr_vals.into_bytes(),
    };

    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(26); // OP_READDIR
    wire.write_u32(0); // status
    wire.write_fixed_opaque(&[1; 8]); // cookieverf
    wire.write_bool(true); // entry follows
    wire.write_u64(7); // cookie
    wire.write_string("file.txt", 1024).unwrap();
    attrs.encode(&mut wire).unwrap();
    wire.write_bool(false); // no more entries
    wire.write_bool(true); // eof

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    let OperationResult::ReadDir {
        cookieverf,
        entries,
        eof,
        ..
    } = &response.results[0]
    else {
        panic!("expected READDIR result");
    };
    assert_eq!(*cookieverf, [1; 8]);
    assert!(*eof);
    assert_eq!(entries[0].cookie, 7);
    assert_eq!(entries[0].name, "file.txt");

    let parsed = entries[0].basic_attributes().unwrap();
    assert_eq!(parsed.file_type, Some(FileType::Regular));
    assert_eq!(parsed.size, Some(512));
}

#[test]
fn builds_and_queries_v4_bitmaps() {
    let bitmap = Bitmap::from_attrs(FATTR4_BASIC_ATTRS);
    assert!(bitmap.contains(FATTR4_TYPE));
    assert!(bitmap.contains(FATTR4_CHANGE));
    assert!(bitmap.contains(FATTR4_SIZE));
    assert!(bitmap.contains(FATTR4_FILEID));
    assert!(bitmap.contains(FATTR4_MODE));
    assert!(bitmap.contains(FATTR4_NUMLINKS));
    assert!(bitmap.contains(FATTR4_OWNER));
    assert!(bitmap.contains(FATTR4_OWNER_GROUP));
    assert!(bitmap.contains(FATTR4_SPACE_USED));
    assert!(bitmap.contains(FATTR4_TIME_ACCESS));
    assert!(bitmap.contains(FATTR4_TIME_METADATA));
    assert!(bitmap.contains(FATTR4_TIME_MODIFY));
    assert!(!bitmap.contains(99));
}

#[test]
fn filters_v4_attr_requests_by_supported_attrs() {
    let supported = Bitmap::from_attrs(&[FATTR4_TYPE, FATTR4_SIZE, FATTR4_SPACE_TOTAL]);
    let request = Bitmap::from_supported_attrs(&supported, FATTR4_BASIC_ATTRS);

    assert!(!request.is_empty());
    assert!(request.contains(FATTR4_TYPE));
    assert!(request.contains(FATTR4_SIZE));
    assert!(!request.contains(FATTR4_MODE));
    assert!(Bitmap::from_supported_attrs(&Bitmap::empty(), FATTR4_BASIC_ATTRS).is_empty());
}

#[test]
fn parses_v4_supported_attrs_attribute() {
    let supported = Bitmap::from_attrs(&[FATTR4_TYPE, FATTR4_SIZE, FATTR4_MODE]);
    let attrs = Fattr {
        attrmask: Bitmap::from_attrs(&[FATTR4_SUPPORTED_ATTRS]),
        attr_vals: to_bytes(&supported).unwrap(),
    };
    let parsed = attrs.parse_supported_attrs().unwrap();

    assert!(parsed.contains(FATTR4_TYPE));
    assert!(parsed.contains(FATTR4_SIZE));
    assert!(parsed.contains(FATTR4_MODE));
    assert!(!parsed.contains(FATTR4_SPACE_TOTAL));
}

#[test]
fn parses_basic_v4_attributes() {
    let mut attr_vals = Encoder::new();
    attr_vals.write_u32(1); // NF4REG
    attr_vals.write_u64(9);
    attr_vals.write_u64(123);
    attr_vals.write_u64(456);
    attr_vals.write_u32(0o644);
    attr_vals.write_u32(2);
    attr_vals.write_string("alice", 1024).unwrap();
    attr_vals.write_string("staff", 1024).unwrap();
    attr_vals.write_u64(4096);
    attr_vals.write_i64(10);
    attr_vals.write_u32(11);
    attr_vals.write_i64(12);
    attr_vals.write_u32(13);
    attr_vals.write_i64(14);
    attr_vals.write_u32(15);

    let attrs = Fattr {
        attrmask: Bitmap::from_attrs(FATTR4_BASIC_ATTRS),
        attr_vals: attr_vals.into_bytes(),
    };
    let parsed = attrs.parse_basic().unwrap();

    assert_eq!(parsed.file_type, Some(FileType::Regular));
    assert_eq!(parsed.change, Some(9));
    assert_eq!(parsed.size, Some(123));
    assert_eq!(parsed.fileid, Some(456));
    assert_eq!(parsed.mode, Some(0o644));
    assert_eq!(parsed.numlinks, Some(2));
    assert_eq!(parsed.owner.as_deref(), Some("alice"));
    assert_eq!(parsed.owner_group.as_deref(), Some("staff"));
    assert_eq!(parsed.space_used, Some(4096));
    assert_eq!(
        parsed.access_time,
        Some(NfsTime {
            seconds: 10,
            nseconds: 11
        })
    );
    assert_eq!(
        parsed.metadata_time,
        Some(NfsTime {
            seconds: 12,
            nseconds: 13
        })
    );
    assert_eq!(
        parsed.modify_time,
        Some(NfsTime {
            seconds: 14,
            nseconds: 15
        })
    );
    assert!(parsed.is_file().unwrap());
    assert!(!parsed.is_dir().unwrap());
}

#[test]
fn classifies_v4_file_types() {
    assert!(FileType::Regular.is_file());
    assert!(FileType::Directory.is_dir());
    assert!(FileType::Symlink.is_symlink());
    assert!(!FileType::NamedAttr.is_file());

    let attrs = nfs::v4::BasicAttributes {
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
        raw: Fattr::empty(),
    };
    assert!(attrs.required_file_type().is_err());
}

#[test]
fn builds_v4_setattr_payloads() {
    let attrs = SetAttrs {
        size: Some(5),
        mode: Some(0o600),
        owner: Some("alice".to_owned()),
        owner_group: Some("staff".to_owned()),
        access_time: SetTime::ServerTime,
        modify_time: SetTime::ClientTime(NfsTime {
            seconds: 42,
            nseconds: 7,
        }),
    };
    let fattr = Fattr::from_set_attrs(&attrs).unwrap();

    assert!(fattr.attrmask.contains(FATTR4_SIZE));
    assert!(fattr.attrmask.contains(FATTR4_MODE));
    assert!(fattr.attrmask.contains(FATTR4_OWNER));
    assert!(fattr.attrmask.contains(FATTR4_OWNER_GROUP));
    assert!(fattr.attrmask.contains(FATTR4_TIME_ACCESS_SET));
    assert!(fattr.attrmask.contains(FATTR4_TIME_MODIFY_SET));

    let mut decoder = Decoder::new(&fattr.attr_vals);
    assert_eq!(decoder.read_u64().unwrap(), 5);
    assert_eq!(decoder.read_u32().unwrap(), 0o600);
    assert_eq!(decoder.read_string(1024).unwrap(), "alice");
    assert_eq!(decoder.read_string(1024).unwrap(), "staff");
    assert_eq!(decoder.read_u32().unwrap(), 0);
    assert_eq!(decoder.read_u32().unwrap(), 1);
    assert_eq!(decoder.read_i64().unwrap(), 42);
    assert_eq!(decoder.read_u32().unwrap(), 7);
    decoder.finish().unwrap();
}

#[test]
fn parses_v4_fsstat_attributes() {
    let bitmap = Bitmap::from_attrs(FATTR4_FSSTAT_ATTRS);
    assert!(bitmap.contains(FATTR4_FILES_AVAIL));
    assert!(bitmap.contains(FATTR4_FILES_FREE));
    assert!(bitmap.contains(FATTR4_FILES_TOTAL));
    assert!(bitmap.contains(FATTR4_SPACE_AVAIL));
    assert!(bitmap.contains(FATTR4_SPACE_FREE));
    assert!(bitmap.contains(FATTR4_SPACE_TOTAL));

    let mut attr_vals = Encoder::new();
    attr_vals.write_u64(10); // files_avail
    attr_vals.write_u64(11); // files_free
    attr_vals.write_u64(12); // files_total
    attr_vals.write_u64(100); // space_avail
    attr_vals.write_u64(101); // space_free
    attr_vals.write_u64(102); // space_total

    let attrs = Fattr {
        attrmask: bitmap,
        attr_vals: attr_vals.into_bytes(),
    };
    let parsed = attrs.parse_fsstat().unwrap();

    assert_eq!(parsed.available_files, Some(10));
    assert_eq!(parsed.free_files, Some(11));
    assert_eq!(parsed.total_files, Some(12));
    assert_eq!(parsed.available_bytes, Some(100));
    assert_eq!(parsed.free_bytes, Some(101));
    assert_eq!(parsed.total_bytes, Some(102));
}

#[test]
fn parses_v4_fsinfo_attributes() {
    let bitmap = Bitmap::from_attrs(FATTR4_FSINFO_ATTRS);
    assert!(bitmap.contains(FATTR4_FH_EXPIRE_TYPE));
    assert!(bitmap.contains(FATTR4_LINK_SUPPORT));
    assert!(bitmap.contains(FATTR4_SYMLINK_SUPPORT));
    assert!(bitmap.contains(FATTR4_UNIQUE_HANDLES));
    assert!(bitmap.contains(FATTR4_LEASE_TIME));
    assert!(bitmap.contains(FATTR4_HOMOGENEOUS));
    assert!(bitmap.contains(FATTR4_MAXFILESIZE));
    assert!(bitmap.contains(FATTR4_MAXREAD));
    assert!(bitmap.contains(FATTR4_MAXWRITE));
    assert!(bitmap.contains(FATTR4_TIME_DELTA));

    let mut attr_vals = Encoder::new();
    attr_vals.write_u32(0x0000_0001); // fh_expire_type
    attr_vals.write_bool(true); // link_support
    attr_vals.write_bool(false); // symlink_support
    attr_vals.write_bool(true); // unique_handles
    attr_vals.write_u32(90); // lease_time
    attr_vals.write_bool(true); // cansettime
    attr_vals.write_bool(true); // homogeneous
    attr_vals.write_u64(1 << 40); // maxfilesize
    attr_vals.write_u64(128 * 1024); // maxread
    attr_vals.write_u64(256 * 1024); // maxwrite
    attr_vals.write_i64(0); // time_delta.seconds
    attr_vals.write_u32(1); // time_delta.nseconds

    let attrs = Fattr {
        attrmask: bitmap,
        attr_vals: attr_vals.into_bytes(),
    };
    let parsed = attrs.parse_fsinfo().unwrap();

    assert_eq!(parsed.fh_expire_type, Some(1));
    assert_eq!(parsed.link_support, Some(true));
    assert_eq!(parsed.symlink_support, Some(false));
    assert_eq!(parsed.unique_handles, Some(true));
    assert_eq!(parsed.lease_time_seconds, Some(90));
    assert_eq!(parsed.can_set_time, Some(true));
    assert_eq!(parsed.homogeneous, Some(true));
    assert_eq!(parsed.max_file_size, Some(1 << 40));
    assert_eq!(parsed.max_read, Some(128 * 1024));
    assert_eq!(parsed.max_write, Some(256 * 1024));
    assert_eq!(
        parsed.time_delta,
        Some(NfsTime {
            seconds: 0,
            nseconds: 1
        })
    );
}

#[test]
fn parses_v4_pathconf_attributes() {
    let bitmap = Bitmap::from_attrs(FATTR4_PATHCONF_ATTRS);
    assert!(bitmap.contains(FATTR4_CASE_INSENSITIVE));
    assert!(bitmap.contains(FATTR4_CASE_PRESERVING));
    assert!(bitmap.contains(FATTR4_CHOWN_RESTRICTED));
    assert!(bitmap.contains(FATTR4_MAXLINK));
    assert!(bitmap.contains(FATTR4_MAXNAME));
    assert!(bitmap.contains(FATTR4_NO_TRUNC));

    let mut attr_vals = Encoder::new();
    attr_vals.write_bool(false); // case_insensitive
    attr_vals.write_bool(true); // case_preserving
    attr_vals.write_bool(true); // chown_restricted
    attr_vals.write_u32(127); // maxlink
    attr_vals.write_u32(255); // maxname
    attr_vals.write_bool(true); // no_trunc

    let attrs = Fattr {
        attrmask: bitmap,
        attr_vals: attr_vals.into_bytes(),
    };
    let parsed = attrs.parse_pathconf().unwrap();

    assert_eq!(parsed.case_insensitive, Some(false));
    assert_eq!(parsed.case_preserving, Some(true));
    assert_eq!(parsed.chown_restricted, Some(true));
    assert_eq!(parsed.link_max, Some(127));
    assert_eq!(parsed.name_max, Some(255));
    assert_eq!(parsed.no_trunc, Some(true));
}

#[test]
fn encodes_anonymous_stateid_for_special_read_state() {
    let bytes = to_bytes(&StateId::anonymous()).unwrap();
    assert_eq!(bytes, vec![0; 16]);
}

#[test]
fn encodes_destroy_session_operation() {
    let bytes = to_bytes(&Operation::DestroySession([1; 16])).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(44); // OP_DESTROY_SESSION
    expected.write_fixed_opaque(&[1; 16]);
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_access_operation() {
    let bytes = to_bytes(&Operation::Access(ACCESS4_READ | ACCESS4_LOOKUP)).unwrap();
    assert_eq!(
        bytes,
        vec![
            0, 0, 0, 3, // OP_ACCESS
            0, 0, 0, 3, // ACCESS4_READ | ACCESS4_LOOKUP
        ]
    );
}

#[test]
fn encodes_link_operation() {
    let bytes = to_bytes(&Operation::Link("alias".to_owned())).unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(11); // OP_LINK
    expected.write_string("alias", 1024).unwrap();
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_commit_operation() {
    let bytes = to_bytes(&Operation::Commit {
        offset: 0x0102_0304_0506_0708,
        count: 4096,
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(5); // OP_COMMIT
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_u32(4096);
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_v42_space_management_operations() {
    let stateid = StateId {
        seqid: 3,
        other: [4; 12],
    };

    let allocate = to_bytes(&Operation::Allocate {
        stateid,
        offset: 0x0102_0304_0506_0708,
        length: 0x1112_1314_1516_1718,
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(59); // OP_ALLOCATE
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_u64(0x1112_1314_1516_1718);
    assert_eq!(allocate, expected.into_bytes());

    let deallocate = to_bytes(&Operation::Deallocate {
        stateid,
        offset: 1024,
        length: 4096,
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(62); // OP_DEALLOCATE
    expected.write_u32(3);
    expected.write_fixed_opaque(&[4; 12]);
    expected.write_u64(1024);
    expected.write_u64(4096);
    assert_eq!(deallocate, expected.into_bytes());
}

#[test]
fn encodes_v42_seek_operation() {
    let bytes = to_bytes(&Operation::Seek {
        stateid: StateId {
            seqid: 5,
            other: [6; 12],
        },
        offset: 0x0102_0304_0506_0708,
        what: SeekContent::Hole,
    })
    .unwrap();

    let mut expected = Encoder::new();
    expected.write_u32(69); // OP_SEEK
    expected.write_u32(5);
    expected.write_fixed_opaque(&[6; 12]);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_u32(1); // NFS4_CONTENT_HOLE
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_setattr_mode_operation() {
    let bytes = to_bytes(&Operation::SetAttr {
        stateid: StateId::anonymous(),
        attrs: Fattr::mode(0o600),
    })
    .unwrap();
    let mut expected = Encoder::new();
    expected.write_u32(34); // OP_SETATTR
    expected.write_fixed_opaque(&[0; 16]);
    expected.write_u32(2); // bitmap words
    expected.write_u32(0);
    expected.write_u32(1 << (FATTR4_MODE - 32));
    expected
        .write_opaque(&0o600_u32.to_be_bytes(), 64 * 1024 * 1024)
        .unwrap();
    assert_eq!(bytes, expected.into_bytes());
}

#[test]
fn encodes_open_create_and_write_operations() {
    let open = Operation::Open(OpenArgs {
        seqid: 7,
        share_access: OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
        share_deny: OPEN4_SHARE_DENY_NONE,
        owner: OpenOwner {
            client_id: 0x0102_0304_0506_0708,
            owner: b"o".to_vec(),
        },
        openhow: OpenHow::Unchecked(Fattr::mode(0o644)),
        claim: OpenClaim::Null("file".to_owned()),
    });
    let mut expected = Encoder::new();
    expected.write_u32(18); // OP_OPEN
    expected.write_u32(7);
    expected.write_u32(OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG);
    expected.write_u32(OPEN4_SHARE_DENY_NONE);
    expected.write_u64(0x0102_0304_0506_0708);
    expected.write_opaque(b"o", 1024).unwrap();
    expected.write_u32(1); // OPEN4_CREATE
    expected.write_u32(0); // UNCHECKED4
    expected.write_u32(2); // bitmap words
    expected.write_u32(0);
    expected.write_u32(1 << (FATTR4_MODE - 32));
    expected
        .write_opaque(&0o644_u32.to_be_bytes(), 64 * 1024 * 1024)
        .unwrap();
    expected.write_u32(0); // CLAIM_NULL
    expected.write_string("file", 1024).unwrap();
    assert_eq!(to_bytes(&open).unwrap(), expected.into_bytes());

    let create = Operation::Create(CreateArgs {
        kind: CreateKind::Directory,
        name: "dir".to_owned(),
        attrs: Fattr::mode(0o755),
    });
    let mut expected = Encoder::new();
    expected.write_u32(6); // OP_CREATE
    expected.write_u32(2); // NF4DIR
    expected.write_string("dir", 1024).unwrap();
    expected.write_u32(2);
    expected.write_u32(0);
    expected.write_u32(1 << (FATTR4_MODE - 32));
    expected
        .write_opaque(&0o755_u32.to_be_bytes(), 64 * 1024 * 1024)
        .unwrap();
    assert_eq!(to_bytes(&create).unwrap(), expected.into_bytes());

    let symlink = Operation::Create(CreateArgs {
        kind: CreateKind::Symlink("target".to_owned()),
        name: "link".to_owned(),
        attrs: Fattr::empty(),
    });
    let mut expected = Encoder::new();
    expected.write_u32(6); // OP_CREATE
    expected.write_u32(5); // NF4LNK
    expected.write_string("target", 1024).unwrap();
    expected.write_string("link", 1024).unwrap();
    expected.write_u32(0); // empty bitmap
    expected.write_u32(0); // empty attr_vals
    assert_eq!(to_bytes(&symlink).unwrap(), expected.into_bytes());

    let write = Operation::Write {
        stateid: StateId {
            seqid: 1,
            other: [2; 12],
        },
        offset: 9,
        stable: StableHow::FileSync,
        data: b"abc".to_vec(),
    };
    let mut expected = Encoder::new();
    expected.write_u32(38); // OP_WRITE
    expected.write_u32(1);
    expected.write_fixed_opaque(&[2; 12]);
    expected.write_u64(9);
    expected.write_u32(2); // FILE_SYNC4
    expected.write_opaque(b"abc", 64 * 1024 * 1024).unwrap();
    assert_eq!(to_bytes(&write).unwrap(), expected.into_bytes());
}

#[test]
fn decodes_open_write_and_create_results() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(5); // result count
    wire.write_u32(18); // OP_OPEN
    wire.write_u32(0); // status
    wire.write_u32(9); // stateid seqid
    wire.write_fixed_opaque(&[1; 12]);
    wire.write_bool(true); // change_info atomic
    wire.write_u64(1);
    wire.write_u64(2);
    wire.write_u32(0); // result flags
    wire.write_u32(0); // attrset bitmap
    wire.write_u32(0); // OPEN_DELEGATE_NONE
    wire.write_u32(38); // OP_WRITE
    wire.write_u32(0);
    wire.write_u32(3);
    wire.write_u32(2); // FILE_SYNC4
    wire.write_fixed_opaque(&[8; 8]);
    wire.write_u32(6); // OP_CREATE
    wire.write_u32(0);
    wire.write_bool(true);
    wire.write_u64(3);
    wire.write_u64(4);
    wire.write_u32(0); // attrset bitmap
    wire.write_u32(10); // OP_GETFH
    wire.write_u32(0);
    wire.write_opaque(&[7, 8, 9], 128).unwrap();
    wire.write_u32(27); // OP_READLINK
    wire.write_u32(0);
    wire.write_string("target", 1024).unwrap();

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        &response.results[0],
        OperationResult::Open {
            status: Status::Ok,
            result: Some(result),
        } if result.stateid.seqid == 9 && result.stateid.other == [1; 12]
    ));
    assert!(matches!(
        &response.results[1],
        OperationResult::Write {
            status: Status::Ok,
            result: Some(result),
        } if result.count == 3
            && result.committed == StableHow::FileSync
            && result.verifier == [8; 8]
    ));
    assert!(matches!(
        &response.results[2],
        OperationResult::StatusOnly {
            op,
            status: Status::Ok,
        } if op.name() == "CREATE"
    ));
    assert!(matches!(
        &response.results[3],
        OperationResult::GetFh {
            handle: Some(handle),
            ..
        } if handle.as_bytes() == [7, 8, 9]
    ));
    assert!(matches!(
        &response.results[4],
        OperationResult::ReadLink {
            status: Status::Ok,
            data: Some(target),
        } if target == "target"
    ));
}

#[test]
fn decodes_access_result() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(3); // OP_ACCESS
    wire.write_u32(0); // status
    wire.write_u32(ACCESS4_READ | ACCESS4_LOOKUP); // supported
    wire.write_u32(ACCESS4_READ); // access

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::Access {
            status: Status::Ok,
            result: Some(result),
        }) if result.supported == (ACCESS4_READ | ACCESS4_LOOKUP)
            && result.access == ACCESS4_READ
    ));
}

#[test]
fn decodes_link_result() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(11); // OP_LINK
    wire.write_u32(0); // status
    wire.write_bool(true); // change_info atomic
    wire.write_u64(1);
    wire.write_u64(2);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::StatusOnly {
            op,
            status: Status::Ok,
        }) if *op == OpCode::Link
    ));
}

#[test]
fn decodes_commit_result() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(5); // OP_COMMIT
    wire.write_u32(0); // status
    wire.write_fixed_opaque(&[9; 8]);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::Commit {
            status: Status::Ok,
            result: Some(result),
        }) if result.verifier == [9; 8]
    ));
}

#[test]
fn decodes_seek_result() {
    let mut wire = Encoder::new();
    wire.write_u32(0); // compound status
    wire.write_string("t", 1024).unwrap();
    wire.write_u32(1); // result count
    wire.write_u32(69); // OP_SEEK
    wire.write_u32(0); // status
    wire.write_bool(false); // not EOF
    wire.write_u64(4096);

    let bytes = wire.into_bytes();
    let mut decoder = Decoder::new(&bytes);
    let response = CompoundResponse::decode(&mut decoder).unwrap();
    decoder.finish().unwrap();

    assert!(matches!(
        response.results.first(),
        Some(OperationResult::Seek {
            status: Status::Ok,
            result: Some(result),
        }) if *result == (SeekResult { eof: false, offset: 4096 })
            && result.found_offset() == Some(4096)
    ));

    assert_eq!(
        SeekResult {
            eof: true,
            offset: 8192
        }
        .found_offset(),
        None
    );
}

#[test]
fn compound_error_reports_failing_v4_operation() {
    let response = CompoundResponse {
        status: Status::NoEnt,
        tag: "t".to_owned(),
        results: vec![OperationResult::StatusOnly {
            op: OpCode::Lookup,
            status: Status::NoEnt,
        }],
    };

    let err = response.ensure_ok().unwrap_err();
    assert!(matches!(
        err,
        Error::NfsV4 {
            operation: "LOOKUP",
            status: Status::NoEnt,
        }
    ));
}

#[test]
fn rejects_oversized_v4_file_handles() {
    assert!(FileHandle::new(vec![0; 129]).is_err());
}
