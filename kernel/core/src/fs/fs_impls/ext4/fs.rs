// SPDX-License-Identifier: MPL-2.0

//! Filesystem-level state and VFS `FileSystem` implementation for ext4.

use aster_block::{BlockDevice, bio::BioStatus};
use aster_ext4::{
    MAGIC as EXT4_MAGIC,
    reader::{extent_tree_from, geometry_from, read_inode_from},
};

use super::{device::DeviceReader, inode::Ext4Inode};
use crate::{
    fs::{
        utils::NAME_MAX,
        vfs::{
            file_system::{FileSystem, FsEventSubscriberStats, FsFlags, SuperBlock},
            inode::Inode,
        },
    },
    prelude::*,
};

pub(super) struct Ext4 {
    device: Arc<dyn BlockDevice>,
    reader: Arc<DeviceReader>,
    info: aster_ext4::Info,
    geometry: aster_ext4::reader::Geometry,
    flags: FsFlags,
    writable: bool,
    journal_start: u64,
    fs_event_subscriber_stats: FsEventSubscriberStats,
    self_ref: Weak<Self>,
}

impl Ext4 {
    pub(super) fn open(
        device: Arc<dyn BlockDevice>,
        flags: FsFlags,
        _data: Option<&str>,
    ) -> Result<Arc<Self>> {
        let writable = cfg!(feature = "ext4_rw_experimental") && !flags.contains(FsFlags::RDONLY);
        let reader = Arc::new(DeviceReader::new(device.clone()));
        let info = analyze_device(&reader)?;
        let geometry = geometry_from(reader.as_ref()).map_err(|error| {
            error!("ext4: invalid geometry: {:?}", error);
            errno!(EINVAL, "invalid ext4 geometry")
        })?;
        let block_size = geometry.block_size;
        if !matches!(block_size, 1024 | 2048 | 4096) {
            return Err(errno!(EINVAL, "unsupported ext4 block size"));
        }
        let journal_start = if writable {
            let journal_inode = read_inode_from(reader.as_ref(), &geometry, info.journal_inum)
                .map_err(|_| errno!(EINVAL, "cannot read ext4 journal inode"))?;
            let extents = extent_tree_from(reader.as_ref(), &geometry, &journal_inode)
                .map_err(|_| errno!(EINVAL, "cannot read ext4 journal extents"))?;
            let first = extents.first().ok_or_else(|| errno!(EINVAL, "ext4 journal has no extents"))?;
            first
                .physical_block
                .checked_mul(block_size as u64)
                .ok_or_else(|| errno!(EINVAL, "ext4 journal offset overflow"))?
        } else {
            0
        };

        Ok(Arc::new_cyclic(|self_ref| Self {
            device,
            reader,
            info,
            geometry,
            flags: if writable {
                FsFlags::empty()
            } else {
                FsFlags::RDONLY
            },
            writable,
            journal_start,
            fs_event_subscriber_stats: FsEventSubscriberStats::new(),
            self_ref: self_ref.clone(),
        }))
    }

    pub(super) fn reader(&self) -> &Arc<DeviceReader> {
        &self.reader
    }

    pub(super) fn geometry(&self) -> &aster_ext4::reader::Geometry {
        &self.geometry
    }

    pub(super) fn device(&self) -> &Arc<dyn BlockDevice> {
        &self.device
    }

    pub(super) fn writable(&self) -> bool {
        self.writable
    }

    pub(super) fn metadata_checksum_seed(&self) -> Option<u32> {
        self.info.metadata_checksum_seed
    }

    pub(super) fn journal_start(&self) -> u64 {
        self.journal_start
    }

    pub(super) fn upgrade(&self) -> Option<Arc<Self>> {
        self.self_ref.upgrade()
    }
}

fn analyze_device(reader: &DeviceReader) -> Result<aster_ext4::Info> {
    aster_ext4::analyze_from(reader).map_err(|error| {
        match error {
            aster_ext4::Error::NeedsRecovery | aster_ext4::Error::Unclean => {
                errno!(EINVAL, "ext4 image needs journal recovery")
            }
            aster_ext4::Error::UnsupportedFeature(_) => {
                errno!(EINVAL, "unsupported ext4 incompatible features")
            }
            _ => errno!(EINVAL, "invalid ext4 superblock"),
        }
    })
}

impl FileSystem for Ext4 {
    fn name(&self) -> &'static str {
        "ext4"
    }

    fn sync(&self) -> Result<()> {
        if self.device.sync()? != BioStatus::Complete {
            return Err(errno!(EIO, "failed to flush block device"));
        }
        Ok(())
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        Ext4Inode::new(
            self.upgrade().expect("ext4 root inode outlives its filesystem"),
            aster_ext4::reader::ROOT_INO,
        )
    }

    fn sb(&self) -> SuperBlock {
        let info = &self.info;
        SuperBlock {
            magic: EXT4_MAGIC as u64,
            bsize: info.block_size,
            blocks: info.blocks_count as usize,
            bfree: info.free_blocks_count as usize,
            bavail: info
                .free_blocks_count
                .saturating_sub(info.reserved_blocks_count) as usize,
            files: info.inodes_count as usize,
            ffree: info.free_inodes_count as usize,
            fsid: 0,
            namelen: NAME_MAX,
            frsize: info.block_size,
            flags: 0,
            container_dev_id: self.device.id(),
        }
    }

    fn max_name_len(&self) -> usize {
        NAME_MAX
    }

    fn flags(&self) -> FsFlags {
        self.flags
    }

    fn fs_event_subscriber_stats(&self) -> &FsEventSubscriberStats {
        &self.fs_event_subscriber_stats
    }
}
