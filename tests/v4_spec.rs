#![cfg(feature = "protocol")]

use nfs::v4::protocol::*;
use nfs::xdr::to_bytes;

#[test]
fn rfc7530_8881_7862_program_constants_match_spec() {
    assert_eq!(NFS4_PROGRAM, 100003);
    assert_eq!(NFS4_VERSION, 4);
    assert_eq!(NFS4_PORT, 2049);
    assert_eq!(NFS4_MINOR_VERSION_LATEST, 2);
    assert_eq!(NFS4_FHSIZE, 128);
    assert_eq!(NFS4_VERIFIER_SIZE, 8);
    assert_eq!(NFS4_SESSIONID_SIZE, 16);
    assert_eq!(NFS4_OPAQUE_LIMIT, 1024);
}

#[test]
fn rfc7530_access_and_file_type_constants_match_spec() {
    assert_eq!(ACCESS4_READ, 0x0001);
    assert_eq!(ACCESS4_LOOKUP, 0x0002);
    assert_eq!(ACCESS4_MODIFY, 0x0004);
    assert_eq!(ACCESS4_EXTEND, 0x0008);
    assert_eq!(ACCESS4_DELETE, 0x0010);
    assert_eq!(ACCESS4_EXECUTE, 0x0020);

    assert_eq!(OPEN4_SHARE_ACCESS_READ, 0x0000_0001);
    assert_eq!(OPEN4_SHARE_ACCESS_WRITE, 0x0000_0002);
    assert_eq!(OPEN4_SHARE_ACCESS_BOTH, 0x0000_0003);
    assert_eq!(OPEN4_SHARE_ACCESS_WANT_NO_DELEG, 0x0000_0400);
    assert_eq!(OPEN4_SHARE_DENY_NONE, 0);

    assert_eq!(NF4REG, 1);
    assert_eq!(NF4DIR, 2);
    assert_eq!(NF4BLK, 3);
    assert_eq!(NF4CHR, 4);
    assert_eq!(NF4LNK, 5);
    assert_eq!(NF4SOCK, 6);
    assert_eq!(NF4FIFO, 7);
}

#[test]
fn rfc7530_8881_7862_attribute_numbers_match_spec() {
    let attrs = [
        (FATTR4_SUPPORTED_ATTRS, 0),
        (FATTR4_TYPE, 1),
        (FATTR4_FH_EXPIRE_TYPE, 2),
        (FATTR4_CHANGE, 3),
        (FATTR4_SIZE, 4),
        (FATTR4_LINK_SUPPORT, 5),
        (FATTR4_SYMLINK_SUPPORT, 6),
        (FATTR4_UNIQUE_HANDLES, 9),
        (FATTR4_LEASE_TIME, 10),
        (FATTR4_CANSETTIME, 15),
        (FATTR4_CASE_INSENSITIVE, 16),
        (FATTR4_CASE_PRESERVING, 17),
        (FATTR4_CHOWN_RESTRICTED, 18),
        (FATTR4_FILEID, 20),
        (FATTR4_FILES_AVAIL, 21),
        (FATTR4_FILES_FREE, 22),
        (FATTR4_FILES_TOTAL, 23),
        (FATTR4_HOMOGENEOUS, 26),
        (FATTR4_MAXFILESIZE, 27),
        (FATTR4_MAXLINK, 28),
        (FATTR4_MAXNAME, 29),
        (FATTR4_MAXREAD, 30),
        (FATTR4_MAXWRITE, 31),
        (FATTR4_MODE, 33),
        (FATTR4_NO_TRUNC, 34),
        (FATTR4_NUMLINKS, 35),
        (FATTR4_OWNER, 36),
        (FATTR4_OWNER_GROUP, 37),
        (FATTR4_SPACE_AVAIL, 42),
        (FATTR4_SPACE_FREE, 43),
        (FATTR4_SPACE_TOTAL, 44),
        (FATTR4_SPACE_USED, 45),
        (FATTR4_TIME_ACCESS, 47),
        (FATTR4_TIME_ACCESS_SET, 48),
        (FATTR4_TIME_DELTA, 51),
        (FATTR4_TIME_METADATA, 52),
        (FATTR4_TIME_MODIFY, 53),
        (FATTR4_TIME_MODIFY_SET, 54),
    ];

    for (actual, expected) in attrs {
        assert_eq!(actual, expected);
    }

    assert_eq!(
        FATTR4_BASIC_ATTRS,
        &[
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
        ]
    );
    assert_eq!(
        FATTR4_FSSTAT_ATTRS,
        &[
            FATTR4_FILES_AVAIL,
            FATTR4_FILES_FREE,
            FATTR4_FILES_TOTAL,
            FATTR4_SPACE_AVAIL,
            FATTR4_SPACE_FREE,
            FATTR4_SPACE_TOTAL,
        ]
    );
    assert_eq!(
        FATTR4_PATHCONF_ATTRS,
        &[
            FATTR4_CASE_INSENSITIVE,
            FATTR4_CASE_PRESERVING,
            FATTR4_CHOWN_RESTRICTED,
            FATTR4_MAXLINK,
            FATTR4_MAXNAME,
            FATTR4_NO_TRUNC,
        ]
    );
}

#[test]
fn rfc7530_8881_7862_status_codes_round_trip() {
    let statuses = [
        (0, Status::Ok),
        (1, Status::Perm),
        (2, Status::NoEnt),
        (5, Status::Io),
        (6, Status::Nxio),
        (13, Status::Access),
        (17, Status::Exist),
        (18, Status::Xdev),
        (20, Status::NotDir),
        (21, Status::IsDir),
        (22, Status::Inval),
        (27, Status::Fbig),
        (28, Status::NoSpc),
        (30, Status::ReadOnlyFs),
        (31, Status::Mlink),
        (63, Status::NameTooLong),
        (66, Status::NotEmpty),
        (69, Status::Dquot),
        (70, Status::Stale),
        (10001, Status::BadHandle),
        (10003, Status::BadCookie),
        (10004, Status::NotSupported),
        (10005, Status::TooSmall),
        (10006, Status::ServerFault),
        (10007, Status::BadType),
        (10008, Status::Delay),
        (10011, Status::Expired),
        (10013, Status::Grace),
        (10016, Status::WrongSec),
        (10020, Status::NoFileHandle),
        (10021, Status::MinorVersionMismatch),
        (10022, Status::StaleClientId),
        (10023, Status::StaleStateId),
        (10024, Status::OldStateId),
        (10025, Status::BadStateId),
        (10031, Status::LeaseMoved),
        (10047, Status::AdminRevoked),
        (10052, Status::BadSession),
        (10063, Status::SeqMisordered),
        (10071, Status::OpNotInSession),
        (10076, Status::SeqFalseRetry),
        (10078, Status::DeadSession),
        (10083, Status::WrongType),
        (10090, Status::UnionNotSupported),
    ];

    for (code, status) in statuses {
        assert_eq!(Status::from_u32(code), status);
        assert_eq!(status.as_u32(), code);
    }
    assert_eq!(Status::from_u32(4242), Status::Unknown(4242));
    assert_eq!(Status::Unknown(4242).as_u32(), 4242);
}

#[test]
fn rfc8881_session_and_state_statuses_are_classified() {
    assert!(Status::BadSession.requires_session_recovery());
    assert!(Status::DeadSession.requires_session_recovery());
    assert!(Status::StaleClientId.requires_session_recovery());
    assert!(!Status::BadStateId.requires_session_recovery());

    assert!(Status::AdminRevoked.indicates_lost_state());
    assert!(Status::BadStateId.indicates_lost_state());
    assert!(Status::Expired.indicates_lost_state());
    assert!(Status::LeaseMoved.indicates_lost_state());
    assert!(Status::OldStateId.indicates_lost_state());
    assert!(Status::StaleClientId.indicates_lost_state());
    assert!(Status::StaleStateId.indicates_lost_state());
    assert!(!Status::Delay.indicates_lost_state());
}

#[test]
fn rfc7530_8881_7862_operation_codes_round_trip() {
    let opcodes = [
        (3, OpCode::Access, "ACCESS"),
        (4, OpCode::Close, "CLOSE"),
        (5, OpCode::Commit, "COMMIT"),
        (6, OpCode::Create, "CREATE"),
        (9, OpCode::GetAttr, "GETATTR"),
        (10, OpCode::GetFh, "GETFH"),
        (11, OpCode::Link, "LINK"),
        (15, OpCode::Lookup, "LOOKUP"),
        (16, OpCode::Lookupp, "LOOKUPP"),
        (18, OpCode::Open, "OPEN"),
        (22, OpCode::PutFh, "PUTFH"),
        (23, OpCode::PutPubFh, "PUTPUBFH"),
        (24, OpCode::PutRootFh, "PUTROOTFH"),
        (25, OpCode::Read, "READ"),
        (26, OpCode::ReadDir, "READDIR"),
        (27, OpCode::ReadLink, "READLINK"),
        (28, OpCode::Remove, "REMOVE"),
        (29, OpCode::Rename, "RENAME"),
        (31, OpCode::RestoreFh, "RESTOREFH"),
        (32, OpCode::SaveFh, "SAVEFH"),
        (34, OpCode::SetAttr, "SETATTR"),
        (38, OpCode::Write, "WRITE"),
        (42, OpCode::ExchangeId, "EXCHANGE_ID"),
        (43, OpCode::CreateSession, "CREATE_SESSION"),
        (44, OpCode::DestroySession, "DESTROY_SESSION"),
        (45, OpCode::FreeStateId, "FREE_STATEID"),
        (52, OpCode::SecInfoNoName, "SECINFO_NO_NAME"),
        (53, OpCode::Sequence, "SEQUENCE"),
        (58, OpCode::ReclaimComplete, "RECLAIM_COMPLETE"),
        (59, OpCode::Allocate, "ALLOCATE"),
        (60, OpCode::Copy, "COPY"),
        (61, OpCode::CopyNotify, "COPY_NOTIFY"),
        (62, OpCode::Deallocate, "DEALLOCATE"),
        (63, OpCode::IoAdvise, "IO_ADVISE"),
        (64, OpCode::LayoutError, "LAYOUTERROR"),
        (65, OpCode::LayoutStats, "LAYOUTSTATS"),
        (66, OpCode::OffloadCancel, "OFFLOAD_CANCEL"),
        (67, OpCode::OffloadStatus, "OFFLOAD_STATUS"),
        (68, OpCode::ReadPlus, "READ_PLUS"),
        (69, OpCode::Seek, "SEEK"),
        (70, OpCode::WriteSame, "WRITE_SAME"),
        (71, OpCode::Clone, "CLONE"),
        (10044, OpCode::Illegal, "ILLEGAL"),
    ];

    for (code, opcode, name) in opcodes {
        assert_eq!(OpCode::from_u32(code), Some(opcode));
        assert_eq!(opcode.as_u32(), code);
        assert_eq!(opcode.name(), name);
    }
    assert_eq!(OpCode::from_u32(4242), None);
}

#[test]
fn rfc7530_7862_discriminants_match_spec() {
    assert_eq!(StableHow::Unstable.as_u32(), 0);
    assert_eq!(StableHow::DataSync.as_u32(), 1);
    assert_eq!(StableHow::FileSync.as_u32(), 2);
    assert_eq!(StableHow::from_u32(0), Some(StableHow::Unstable));
    assert_eq!(StableHow::from_u32(1), Some(StableHow::DataSync));
    assert_eq!(StableHow::from_u32(2), Some(StableHow::FileSync));
    assert_eq!(StableHow::from_u32(3), None);

    assert_eq!(SeekContent::Data.as_u32(), 0);
    assert_eq!(SeekContent::Hole.as_u32(), 1);
    assert_eq!(SeekContent::from_u32(0), Some(SeekContent::Data));
    assert_eq!(SeekContent::from_u32(1), Some(SeekContent::Hole));
    assert_eq!(SeekContent::from_u32(2), None);

    let file_types = [
        (1, FileType::Regular),
        (2, FileType::Directory),
        (3, FileType::BlockDevice),
        (4, FileType::CharacterDevice),
        (5, FileType::Symlink),
        (6, FileType::Socket),
        (7, FileType::Fifo),
        (8, FileType::AttrDir),
        (9, FileType::NamedAttr),
    ];
    for (code, file_type) in file_types {
        assert_eq!(FileType::from_u32(code), file_type);
    }
    assert_eq!(FileType::from_u32(4242), FileType::Unknown(4242));
}

#[test]
fn rfc8881_bitmap_word_layout_uses_attribute_number_bits() {
    let bitmap = Bitmap::from_attrs(&[FATTR4_TYPE, FATTR4_MODE, FATTR4_TIME_MODIFY]);

    assert_eq!(
        bitmap.words(),
        &[
            1 << FATTR4_TYPE,
            (1 << (FATTR4_MODE - 32)) | (1 << (FATTR4_TIME_MODIFY - 32))
        ]
    );
    assert!(bitmap.contains(FATTR4_TYPE));
    assert!(bitmap.contains(FATTR4_MODE));
    assert!(bitmap.contains(FATTR4_TIME_MODIFY));
    assert!(!bitmap.contains(FATTR4_SIZE));
}

#[test]
fn implemented_operation_variants_map_to_spec_opcodes() {
    let handle = FileHandle::new(vec![1, 2, 3]).unwrap();
    let stateid = StateId {
        seqid: 7,
        other: [8; 12],
    };
    let exchange = ExchangeIdArgs {
        client_owner: ClientOwner {
            verifier: [1; 8],
            owner_id: b"owner".to_vec(),
        },
        flags: 0,
    };
    let create_session = CreateSessionArgs {
        client_id: 1,
        sequence_id: 2,
        flags: 0,
        fore_channel_attrs: ChannelAttrs::fore_channel_default(),
        back_channel_attrs: ChannelAttrs::back_channel_disabled(),
        callback_program: 0,
    };
    let sequence = SequenceArgs {
        session_id: [9; 16],
        sequence_id: 3,
        slot_id: 0,
        highest_slot_id: 0,
        cache_this: false,
    };
    let open = OpenArgs {
        seqid: 1,
        share_access: OPEN4_SHARE_ACCESS_READ,
        share_deny: OPEN4_SHARE_DENY_NONE,
        owner: OpenOwner {
            client_id: 1,
            owner: b"open".to_vec(),
        },
        openhow: OpenHow::NoCreate,
        claim: OpenClaim::Null("file".to_owned()),
    };

    let operations = [
        (Operation::ExchangeId(exchange), OpCode::ExchangeId),
        (
            Operation::CreateSession(create_session),
            OpCode::CreateSession,
        ),
        (Operation::DestroySession([0; 16]), OpCode::DestroySession),
        (
            Operation::ReclaimComplete { one_fs: false },
            OpCode::ReclaimComplete,
        ),
        (Operation::Sequence(sequence), OpCode::Sequence),
        (Operation::PutRootFh, OpCode::PutRootFh),
        (Operation::PutFh(handle.clone()), OpCode::PutFh),
        (Operation::Lookup("name".to_owned()), OpCode::Lookup),
        (Operation::Access(ACCESS4_READ), OpCode::Access),
        (Operation::Open(open), OpCode::Open),
        (Operation::Close { seqid: 1, stateid }, OpCode::Close),
        (Operation::GetFh, OpCode::GetFh),
        (Operation::GetAttr(Bitmap::empty()), OpCode::GetAttr),
        (
            Operation::SetAttr {
                stateid,
                attrs: Fattr::empty(),
            },
            OpCode::SetAttr,
        ),
        (
            Operation::Read {
                stateid,
                offset: 0,
                count: 1,
            },
            OpCode::Read,
        ),
        (
            Operation::Write {
                stateid,
                offset: 0,
                stable: StableHow::FileSync,
                data: vec![1],
            },
            OpCode::Write,
        ),
        (
            Operation::Allocate {
                stateid,
                offset: 0,
                length: 1,
            },
            OpCode::Allocate,
        ),
        (
            Operation::Deallocate {
                stateid,
                offset: 0,
                length: 1,
            },
            OpCode::Deallocate,
        ),
        (
            Operation::Seek {
                stateid,
                offset: 0,
                what: SeekContent::Data,
            },
            OpCode::Seek,
        ),
        (
            Operation::Commit {
                offset: 0,
                count: 1,
            },
            OpCode::Commit,
        ),
        (
            Operation::ReadDir {
                cookie: 0,
                cookieverf: [0; 8],
                dircount: 1,
                maxcount: 2,
                attr_request: Bitmap::empty(),
            },
            OpCode::ReadDir,
        ),
        (Operation::ReadLink, OpCode::ReadLink),
        (Operation::Remove("name".to_owned()), OpCode::Remove),
        (Operation::Link("name".to_owned()), OpCode::Link),
        (
            Operation::Rename {
                oldname: "old".to_owned(),
                newname: "new".to_owned(),
            },
            OpCode::Rename,
        ),
        (
            Operation::Create(CreateArgs {
                kind: CreateKind::Directory,
                name: "dir".to_owned(),
                attrs: Fattr::empty(),
            }),
            OpCode::Create,
        ),
        (Operation::SaveFh, OpCode::SaveFh),
        (Operation::RestoreFh, OpCode::RestoreFh),
    ];

    for (operation, opcode) in operations {
        assert_eq!(operation.op_code(), opcode);
        assert_eq!(
            &to_bytes(&operation).unwrap()[..4],
            &opcode.as_u32().to_be_bytes()
        );
    }
}
