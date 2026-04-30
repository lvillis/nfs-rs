#![cfg(feature = "blocking")]

use std::env;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use nfs::Result;

#[test]
fn live_v3_roundtrip_when_configured() -> Result<()> {
    let Some(target) = env_var("NFS_RS_V3_TARGET") else {
        return Ok(());
    };
    let prefix = env::var("NFS_RS_TEST_PREFIX").unwrap_or_else(|_| "/".to_owned());
    let root = unique_path(&prefix, "v3");
    let file = join_path(&root, "payload.txt");
    let renamed = join_path(&root, "renamed.txt");
    let created = join_path(&root, "created.txt");
    let atomic = join_path(&root, "atomic.txt");
    let atomic_streamed = join_path(&root, "atomic-streamed.txt");
    let streamed = join_path(&root, "streamed.txt");
    let appended = join_path(&root, "appended.txt");
    let nested_root = join_path(&root, "nested");
    let nested_dir = join_path(&nested_root, "a/b");
    let nested_file = join_path(&nested_dir, "leaf.txt");

    let mut client = nfs::v3::blocking::Client::connect(&target)?;
    client.mkdir(&root, 0o755)?;
    assert!(client.is_dir(&root)?);
    client.create_new(&created, 0o644)?;
    assert!(client.is_file(&created)?);
    assert!(client.create_new(&created, 0o644).is_err());
    assert!(client.remove_if_exists(&created)?);
    assert!(!client.remove_if_exists(&created)?);
    client.create_dir_all(&nested_dir, 0o755)?;
    client.write(&nested_file, b"nested")?;
    assert!(client.is_file(&nested_file)?);
    assert_eq!(client.read(&nested_file)?, b"nested");
    assert!(
        client
            .read_dir_limited(&nested_dir, 16)?
            .iter()
            .any(|entry| entry.name == "leaf.txt")
    );
    let page = client.read_dir_page_limited(&nested_dir, None, 16)?;
    assert!(page.entries.iter().any(|entry| entry.name == "leaf.txt"));
    assert!(client.remove_all_if_exists(&nested_root)?);
    assert!(!client.remove_all_if_exists(&nested_root)?);
    assert!(!client.exists(&nested_root)?);
    client.write(&file, b"nfs-rs-live")?;
    client.write_atomic(&atomic, b"atomic")?;
    assert_eq!(client.read(&atomic)?, b"atomic");
    client.write_atomic(&atomic, b"atomic-replaced")?;
    assert_eq!(client.read(&atomic)?, b"atomic-replaced");
    let mut atomic_reader = Cursor::new(&b"atomic-reader"[..]);
    assert_eq!(
        client.write_atomic_from_reader(&atomic_streamed, &mut atomic_reader)?,
        13
    );
    assert_eq!(client.read(&atomic_streamed)?, b"atomic-reader");
    assert!(client.remove_if_exists(&atomic_streamed)?);
    assert!(client.remove_if_exists(&atomic)?);
    let mut reader = Cursor::new(&b"streamed"[..]);
    assert_eq!(client.write_from_reader(&streamed, &mut reader)?, 8);
    assert_eq!(client.read(&streamed)?, b"streamed");
    client.remove(&streamed)?;
    client.write(&appended, b"a")?;
    assert_eq!(client.append(&appended, b"bc")?, 2);
    let mut append_reader = Cursor::new(&b"de"[..]);
    assert_eq!(client.append_from_reader(&appended, &mut append_reader)?, 2);
    assert_eq!(client.read(&appended)?, b"abcde");
    client.remove(&appended)?;
    assert_eq!(client.read(&file)?, b"nfs-rs-live");
    client.set_mode(&file, 0o600)?;
    assert_eq!(client.metadata(&file)?.mode & 0o777, 0o600);
    assert_eq!(client.read_at(&file, 4, 2)?, b"rs");
    assert_eq!(client.read_exact_at(&file, 4, 2)?, b"rs");
    assert_eq!(client.read_range(&file, 4, 7)?, b"rs-live");
    let mut range = Vec::new();
    assert_eq!(client.read_range_to_writer(&file, 4, 7, &mut range)?, 7);
    assert_eq!(range, b"rs-live");
    client.write_at(&file, 4, b"RS")?;
    assert_eq!(client.read(&file)?, b"nfs-RS-live");
    client.truncate(&file, 6)?;
    assert_eq!(client.read(&file)?, b"nfs-RS");
    client.commit(&file, 0, 0)?;
    client.rename(&file, &renamed)?;
    assert_eq!(client.read(&renamed)?, b"nfs-RS");
    let copied = join_path(&root, "copied.txt");
    let atomic_copied = join_path(&root, "atomic-copied.txt");
    assert_eq!(client.copy(&renamed, &copied)?, 6);
    assert_eq!(client.read(&copied)?, b"nfs-RS");
    assert_eq!(client.copy_atomic(&renamed, &atomic_copied)?, 6);
    assert_eq!(client.read(&atomic_copied)?, b"nfs-RS");
    assert!(client.remove_if_exists(&atomic_copied)?);
    assert!(client.remove_if_exists(&copied)?);
    assert!(client.remove_if_exists(&renamed)?);
    assert!(client.rmdir_if_exists(&root)?);
    assert!(!client.rmdir_if_exists(&root)?);
    Ok(())
}

#[test]
fn live_v4_roundtrip_when_configured() -> Result<()> {
    let Some(host) = env_var("NFS_RS_V4_HOST") else {
        return Ok(());
    };
    let prefix = env::var("NFS_RS_V4_PREFIX")
        .or_else(|_| env::var("NFS_RS_TEST_PREFIX"))
        .unwrap_or_else(|_| "/".to_owned());
    let root = unique_path(&prefix, "v4");
    let file = join_path(&root, "payload.txt");
    let renamed = join_path(&root, "renamed.txt");
    let created = join_path(&root, "created.txt");
    let atomic = join_path(&root, "atomic.txt");
    let atomic_streamed = join_path(&root, "atomic-streamed.txt");
    let streamed = join_path(&root, "streamed.txt");
    let appended = join_path(&root, "appended.txt");
    let nested_root = join_path(&root, "nested");
    let nested_dir = join_path(&nested_root, "a/b");
    let nested_file = join_path(&nested_dir, "leaf.txt");

    let mut client = nfs::v4::blocking::Client::connect(host)?;
    client.renew()?;
    client.mkdir(&root, 0o755)?;
    assert!(client.is_dir(&root)?);
    let _ = client.root_fsinfo();
    let _ = client.fsinfo(&root)?;
    let _ = client.fsstat(&root)?;
    let _ = client.pathconf(&root)?;
    client.create_new_with_mode(&created, 0o644)?;
    assert!(client.is_file(&created)?);
    assert!(client.create_new(&created).is_err());
    assert!(client.remove_if_exists(&created)?);
    assert!(!client.remove_if_exists(&created)?);
    client.create_dir_all(&nested_dir, 0o755)?;
    client.write(&nested_file, b"nested")?;
    assert!(client.is_file(&nested_file)?);
    assert_eq!(client.read(&nested_file)?, b"nested");
    assert!(
        client
            .read_dir_limited(&nested_dir, 16)?
            .iter()
            .any(|entry| entry.name == "leaf.txt")
    );
    let page = client.read_dir_page_limited(&nested_dir, None, 16)?;
    assert!(page.entries.iter().any(|entry| entry.name == "leaf.txt"));
    assert!(client.remove_all_if_exists(&nested_root)?);
    assert!(!client.remove_all_if_exists(&nested_root)?);
    assert!(!client.exists(&nested_root)?);
    client.write(&file, b"nfs-rs-live")?;
    client.write_atomic(&atomic, b"atomic")?;
    assert_eq!(client.read(&atomic)?, b"atomic");
    client.write_atomic_with_mode(&atomic, b"atomic-replaced", 0o644)?;
    assert_eq!(client.read(&atomic)?, b"atomic-replaced");
    let mut atomic_reader = Cursor::new(&b"atomic-reader"[..]);
    assert_eq!(
        client.write_atomic_from_reader(&atomic_streamed, &mut atomic_reader)?,
        13
    );
    assert_eq!(client.read(&atomic_streamed)?, b"atomic-reader");
    assert!(client.remove_if_exists(&atomic_streamed)?);
    assert!(client.remove_if_exists(&atomic)?);
    let mut reader = Cursor::new(&b"streamed"[..]);
    assert_eq!(client.write_from_reader(&streamed, &mut reader)?, 8);
    assert_eq!(client.read(&streamed)?, b"streamed");
    client.remove(&streamed)?;
    client.write(&appended, b"a")?;
    assert_eq!(client.append(&appended, b"bc")?, 2);
    let mut append_reader = Cursor::new(&b"de"[..]);
    assert_eq!(client.append_from_reader(&appended, &mut append_reader)?, 2);
    assert_eq!(client.read(&appended)?, b"abcde");
    client.remove(&appended)?;
    assert_eq!(client.read(&file)?, b"nfs-rs-live");
    client.set_mode(&file, 0o600)?;
    if let Some(mode) = client.metadata(&file)?.mode {
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(client.read_at(&file, 4, 2)?, b"rs");
    assert_eq!(client.read_exact_at(&file, 4, 2)?, b"rs");
    assert_eq!(client.read_range(&file, 4, 7)?, b"rs-live");
    let mut range = Vec::new();
    assert_eq!(client.read_range_to_writer(&file, 4, 7, &mut range)?, 7);
    assert_eq!(range, b"rs-live");
    client.write_at(&file, 4, b"RS")?;
    assert_eq!(client.read(&file)?, b"nfs-RS-live");
    client.truncate(&file, 6)?;
    assert_eq!(client.read(&file)?, b"nfs-RS");
    client.commit(&file, 0, 0)?;
    client.rename(&file, &renamed)?;
    assert_eq!(client.read(&renamed)?, b"nfs-RS");
    let copied = join_path(&root, "copied.txt");
    let atomic_copied = join_path(&root, "atomic-copied.txt");
    assert_eq!(client.copy(&renamed, &copied)?, 6);
    assert_eq!(client.read(&copied)?, b"nfs-RS");
    assert_eq!(client.copy_atomic(&renamed, &atomic_copied)?, 6);
    assert_eq!(client.read(&atomic_copied)?, b"nfs-RS");
    assert!(client.remove_if_exists(&atomic_copied)?);
    assert!(client.remove_if_exists(&copied)?);
    assert!(client.remove_if_exists(&renamed)?);
    assert!(client.rmdir_if_exists(&root)?);
    assert!(!client.rmdir_if_exists(&root)?);
    client.shutdown()
}

fn env_var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn unique_path(prefix: &str, protocol: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    join_path(
        prefix,
        &format!("nfs-rs-live-{protocol}-{}-{nanos}", std::process::id()),
    )
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}
