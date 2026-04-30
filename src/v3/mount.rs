#![cfg_attr(not(feature = "protocol"), allow(dead_code))]

use std::net::ToSocketAddrs;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::rpc::{Auth, AuthSys, RpcClient};
use crate::v3::proto::FileHandle;
use crate::xdr::{Decode, Decoder, Encode, Encoder};

pub const MOUNT_PROGRAM: u32 = 100005;
pub const MOUNT_VERSION: u32 = 3;
pub const MNTPATHLEN: usize = 1024;
pub const MNTNAMLEN: usize = 255;

const MOUNTPROC3_MNT: u32 = 1;
const MOUNTPROC3_UMNT: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MountStatus {
    Ok = 0,
    Perm = 1,
    NoEnt = 2,
    Io = 5,
    Access = 13,
    NotDir = 20,
    Invalid = 22,
    NameTooLong = 63,
    NotSupported = 10004,
    ServerFault = 10006,
    Unknown(u32),
}

impl MountStatus {
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::Perm,
            2 => Self::NoEnt,
            5 => Self::Io,
            13 => Self::Access,
            20 => Self::NotDir,
            22 => Self::Invalid,
            63 => Self::NameTooLong,
            10004 => Self::NotSupported,
            10006 => Self::ServerFault,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub file_handle: FileHandle,
    pub auth_flavors: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirPath<'a>(&'a str);

impl Encode for DirPath<'_> {
    fn encode(&self, encoder: &mut Encoder) -> crate::xdr::Result<()> {
        encoder.write_string(self.0, MNTPATHLEN)
    }
}

#[derive(Debug)]
pub struct MountClient {
    rpc: RpcClient,
}

impl MountClient {
    pub fn connect<A: ToSocketAddrs>(addr: A, auth: AuthSys) -> Result<Self> {
        Self::connect_with_timeout(addr, auth, None)
    }

    pub fn connect_with_timeout<A: ToSocketAddrs>(
        addr: A,
        auth: AuthSys,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        Ok(Self {
            rpc: RpcClient::connect_with_timeout(addr, Auth::sys(auth), timeout)?,
        })
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.rpc.set_timeout(timeout)
    }

    pub fn mount(&mut self, export_path: &str) -> Result<MountInfo> {
        let payload = self.rpc.call(
            MOUNT_PROGRAM,
            MOUNT_VERSION,
            MOUNTPROC3_MNT,
            &DirPath(export_path),
        )?;
        let mut decoder = Decoder::new(&payload);
        let status = MountStatus::from_u32(u32::decode(&mut decoder)?);
        if status != MountStatus::Ok {
            decoder.finish()?;
            return Err(Error::Mount { status });
        }

        let file_handle = FileHandle::decode(&mut decoder)?;
        let auth_flavors = decoder.read_array::<u32>(128)?;
        decoder.finish()?;
        Ok(MountInfo {
            file_handle,
            auth_flavors,
        })
    }

    pub fn unmount(&mut self, export_path: &str) -> Result<()> {
        let payload = self.rpc.call(
            MOUNT_PROGRAM,
            MOUNT_VERSION,
            MOUNTPROC3_UMNT,
            &DirPath(export_path),
        )?;
        let decoder = Decoder::new(&payload);
        decoder.finish()?;
        Ok(())
    }
}
