// SPDX-License-Identifier: MPL-2.0

//! Read-only ext4 support backed by the `aster-ext4` format library.
//!
//! The format, extent and JBD2 parsing lives in `aster-ext4`; this module wires
//! it into the VFS through a block-device-backed `BlockReader`. Mounts are
//! read-only and refuse images that need recovery or carry unsupported
//! features.

use aster_systree::SysNode;
use device_id::DeviceId;

use self::fs::Ext4;
use crate::{
    fs::vfs::{
        file_system::FileSystem,
        registry::{FsCache, FsCreationCtx, FsProperties, FsType},
    },
    prelude::*,
};

mod device;
mod fs;
mod inode;

pub(crate) fn init() {
    crate::fs::vfs::registry::register(&EXT4_TYPE).unwrap();
}

pub(in crate::fs) struct Ext4Type {
    cache: FsCache<DeviceId>,
}

pub(in crate::fs) static EXT4_TYPE: Ext4Type = Ext4Type {
    cache: FsCache::new(),
};

impl FsType for Ext4Type {
    type Key = DeviceId;

    fn name(&self) -> &'static str {
        "ext4"
    }

    fn properties(&self) -> FsProperties {
        FsProperties::NEED_DISK
    }

    fn create(&self, ctx: &mut FsCreationCtx) -> Result<Arc<dyn FileSystem>> {
        let disk = ctx.resolve_block_device()?.clone();
        let flags = ctx.flags();
        let args = ctx.args();
        Ext4::open(disk, flags, args).map(|fs| fs as Arc<dyn FileSystem>)
    }

    fn obtain_key_and_cache(
        &self,
        ctx: &mut FsCreationCtx,
    ) -> Option<(DeviceId, &FsCache<DeviceId>)> {
        let key = ctx.resolve_block_device().ok().map(|disk| disk.id())?;
        Some((key, &self.cache))
    }

    fn sysnode(&self) -> Option<Arc<dyn SysNode>> {
        None
    }
}
