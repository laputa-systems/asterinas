// SPDX-License-Identifier: MPL-2.0

//! VFS `Inode` and `FileOps` implementations for read-only ext4 inodes.

use aster_ext4::{
    reader::{
        DiskEntryType, DirEntry, Inode as RawInode, fast_symlink, inode_number_to_group,
        lookup_from, read_dir_from, read_file_from, read_inode_from,
    },
    write::{WriteEngine, WriteError},
};
use super::fs::Ext4;
use crate::{
    fs::{
        file::{InodeMode, InodeType, StatusFlags, SyncMode},
        utils::DirentVisitor,
        vfs::{
            file_system::FileSystem,
            inode::{Extension, FileOps, Inode, Metadata, SymbolicLink},
            path::Dentry,
        },
    },
    prelude::*,
    process::{Gid, Uid},
    time::FileTime,
};

pub(super) struct Ext4Inode {
    fs: Weak<Ext4>,
    raw: RawInode,
    extension: Extension,
}

impl Ext4Inode {
    pub(super) fn try_new(fs: Arc<Ext4>, ino: u32) -> Result<Arc<dyn Inode>> {
        let raw = read_inode_from(fs.reader().as_ref(), fs.geometry(), ino)
            .map_err(|_| errno!(EIO, "failed to read ext4 inode"))?;
        Ok(Arc::new(Self {
            fs: Arc::downgrade(&fs),
            raw,
            extension: Extension::new(),
        }))
    }

    pub(super) fn new(fs: Arc<Ext4>, ino: u32) -> Arc<dyn Inode> {
        Self::try_new(fs, ino).expect("ext4 root inode must be readable")
    }

    fn fs(&self) -> Result<Arc<Ext4>> {
        self.fs.upgrade().ok_or_else(|| errno!(EIO, "ext4 filesystem is gone"))
    }

    fn read_all(&self) -> Result<Vec<u8>> {
        let fs = self.fs()?;
        read_file_from(
            fs.reader().as_ref(),
            fs.geometry(),
            &self.raw,
        )
        .map_err(|_| errno!(EIO, "failed to read ext4 file data"))
    }

    fn file_type(&self) -> Result<InodeType> {
        InodeType::from_raw_mode(self.raw.mode)
    }

    fn file_time(seconds: u32) -> FileTime {
        FileTime::new(i64::from(seconds), 0)
    }
}

impl FileOps for Ext4Inode {
    fn read_at(
        &self,
        offset: usize,
        writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let data = self.read_all()?;
        if offset >= data.len() {
            return Ok(0);
        }
        let mut reader = VmReader::from(&data[offset..]);
        Ok(writer.write_fallible(&mut reader)?)
    }

    fn write_at(
        &self,
        offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let fs = self.fs()?;
        if !fs.writable() {
            return Err(errno!(EROFS, "ext4 mounts are read-only"));
        }
        let mut data = vec![0u8; reader.remain()];
        let mut writer = VmWriter::from(data.as_mut_slice());
        let written = reader.read_fallible(&mut writer)?;
        data.truncate(written);
        let (group, _) = inode_number_to_group(fs.geometry(), self.raw.number);
        let engine = WriteEngine::new(
            fs.reader().as_ref(),
            fs.reader().as_ref(),
            fs.geometry(),
            &self.raw,
            group,
        );
        match engine.write_at(offset, &data) {
            Ok(()) => Ok(written),
            Err(WriteError::NoSpace) => Err(errno!(ENOSPC, "ext4 journal or data space exhausted")),
            Err(WriteError::TooLarge) => Err(errno!(EINVAL, "ext4 write exceeds the supported size")),
            Err(_) => Err(errno!(EIO, "ext4 write failed")),
        }
    }

    fn readdir_at(&self, offset: usize, visitor: &mut dyn DirentVisitor) -> Result<usize> {
        let fs = self.fs()?;
        let entries: Vec<DirEntry> = read_dir_from(fs.reader().as_ref(), fs.geometry(), &self.raw)
            .map_err(|_| errno!(EIO, "failed to read ext4 directory"))?;
        if entries.is_empty() {
            return Ok(0);
        }
        let mut advanced = 0usize;
        let mut current = offset;
        for (index, entry) in entries.iter().enumerate() {
            let byte_offset = index * 8;
            let next = byte_offset + 8;
            if next <= current {
                continue;
            }
            let ino = entry.ino as u64;
            let type_ = match entry.file_type {
                DiskEntryType::File => InodeType::File,
                DiskEntryType::Dir => InodeType::Dir,
                DiskEntryType::CharDevice => InodeType::CharDevice,
                DiskEntryType::BlockDevice => InodeType::BlockDevice,
                DiskEntryType::Fifo => InodeType::NamedPipe,
                DiskEntryType::Socket => InodeType::Socket,
                DiskEntryType::Symlink => InodeType::SymLink,
                _ => InodeType::Unknown,
            };
            visitor.visit_bytes(&entry.name, ino, type_, next)?;
            current = next;
            advanced = next;
        }
        let _ = &mut current;
        Ok(advanced.saturating_sub(offset))
    }
}

impl Inode for Ext4Inode {
    fn size(&self) -> usize {
        usize::try_from(self.raw.size).unwrap_or(usize::MAX)
    }

    fn resize(&self, _self_dentry: &Dentry, _new_size: usize) -> Result<()> {
        Err(errno!(EROFS, "ext4 mounts are read-only"))
    }

    fn metadata(&self) -> Result<Metadata> {
        let fs = self.fs()?;
        Ok(Metadata {
            ino: u64::from(self.raw.number),
            size: self.size(),
            optimal_block_size: fs.geometry().block_size,
            nr_sectors_allocated: self.raw.blocks as usize * 2,
            last_access_at: Self::file_time(self.raw.atime),
            last_modify_at: Self::file_time(self.raw.mtime),
            last_meta_change_at: Self::file_time(self.raw.ctime),
            type_: self.file_type()?,
            mode: InodeMode::from_bits_truncate(self.raw.mode),
            nr_hard_links: self.raw.links as usize,
            uid: Uid::new(self.raw.uid),
            gid: Gid::new(self.raw.gid),
            container_dev_id: fs.device().id(),
            self_dev_id: None,
            birth_at: None,
        })
    }

    fn ino(&self) -> u64 {
        u64::from(self.raw.number)
    }

    fn type_(&self) -> InodeType {
        self.file_type().unwrap_or(InodeType::Unknown)
    }

    fn mode(&self) -> Result<InodeMode> {
        Ok(InodeMode::from_bits_truncate(self.raw.mode))
    }

    fn set_mode(&self, _self_dentry: &Dentry, _mode: InodeMode) -> Result<()> {
        Err(errno!(EROFS, "ext4 mounts are read-only"))
    }

    fn owner(&self) -> Result<Uid> {
        Ok(Uid::new(self.raw.uid))
    }

    fn set_owner(&self, _self_dentry: &Dentry, _uid: Uid) -> Result<()> {
        Err(errno!(EROFS, "ext4 mounts are read-only"))
    }

    fn group(&self) -> Result<Gid> {
        Ok(Gid::new(self.raw.gid))
    }

    fn set_group(&self, _self_dentry: &Dentry, _gid: Gid) -> Result<()> {
        Err(errno!(EROFS, "ext4 mounts are read-only"))
    }

    fn atime(&self) -> FileTime {
        Self::file_time(self.raw.atime)
    }

    fn set_atime(&self, _self_dentry: &Dentry, _time: FileTime) {}

    fn mtime(&self) -> FileTime {
        Self::file_time(self.raw.mtime)
    }

    fn set_mtime(&self, _self_dentry: &Dentry, _time: FileTime) {}

    fn ctime(&self) -> FileTime {
        Self::file_time(self.raw.ctime)
    }

    fn set_ctime(&self, _self_dentry: &Dentry, _time: FileTime) {}

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        self.lookup_bytes(name.as_bytes())
    }

    fn lookup_bytes(&self, name: &[u8]) -> Result<Arc<dyn Inode>> {
        if self.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let fs = self.fs()?;
        let ino = lookup_from(fs.reader().as_ref(), fs.geometry(), &self.raw, name)
            .ok_or_else(|| errno!(ENOENT, "no such ext4 directory entry"))?;
        Ext4Inode::try_new(fs, ino)
    }

    fn read_link(&self) -> Result<SymbolicLink> {
        if self.type_() != InodeType::SymLink {
            return Err(errno!(EINVAL, "not a symbolic link"));
        }
        if let Some(target) = fast_symlink(&self.raw) {
            return Ok(SymbolicLink::Plain(target));
        }
        Ok(SymbolicLink::Plain(self.read_all()?))
    }

    fn sync(&self, _mode: SyncMode) -> Result<()> {
        self.fs()?.sync()
    }

    fn fs(&self) -> Arc<dyn FileSystem> {
        self.fs()
            .expect("ext4 inode outlives its filesystem") as Arc<dyn FileSystem>
    }

    fn extension(&self) -> &Extension {
        &self.extension
    }
}
