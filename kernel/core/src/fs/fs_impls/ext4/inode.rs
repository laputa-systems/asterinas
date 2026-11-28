// SPDX-License-Identifier: MPL-2.0

//! VFS `Inode` and `FileOps` implementations for ext4 inodes.
//!
//! Cached scalar attributes are atomic so a write can refresh them without a
//! lock held across block I/O. Extent-dependent operations re-read the raw
//! inode from the device on demand, so a write is immediately visible to the
//! next read or lookup even when the VFS reuses the same inode object.

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use aster_ext4::{
    jbd2::JOURNAL_BLOCK_SIZE,
    dir_edit,
    extent_edit::BlockAllocator,
    reader::{
        BlockReader, BlockWriter, DiskEntryType, EXTENT_MAGIC, DirEntry, Inode as RawInode, fast_symlink,
        inode_bitmap_offset_from, inode_number_to_group, inode_offset_from, lookup_from,
        read_dir_from, read_file_from, read_inode_bitmap_from, read_inode_from,
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
            inode::{Extension, FileOps, Inode, Metadata, RenameMode, SymbolicLink},
            path::Dentry,
        },
    },
    prelude::*,
    process::{Gid, Uid},
    time::FileTime,
};

pub(super) struct Ext4Inode {
    fs: Weak<Ext4>,
    number: u32,
    mode: AtomicU16,
    uid: AtomicU32,
    gid: AtomicU32,
    size: AtomicU64,
    links: AtomicU16,
    blocks: AtomicU32,
    flags: AtomicU32,
    atime: AtomicU32,
    ctime: AtomicU32,
    mtime: AtomicU32,
    generation: AtomicU32,
    extension: Extension,
}

impl Ext4Inode {
    pub(super) fn try_new(fs: Arc<Ext4>, ino: u32) -> Result<Arc<dyn Inode>> {
        let raw = Self::read_raw(&fs, ino)?;
        Ok(Arc::new(Self {
            fs: Arc::downgrade(&fs),
            number: ino,
            mode: AtomicU16::new(raw.mode),
            uid: AtomicU32::new(raw.uid),
            gid: AtomicU32::new(raw.gid),
            size: AtomicU64::new(raw.size),
            links: AtomicU16::new(raw.links),
            blocks: AtomicU32::new(raw.blocks),
            flags: AtomicU32::new(raw.flags),
            atime: AtomicU32::new(raw.atime),
            ctime: AtomicU32::new(raw.ctime),
            mtime: AtomicU32::new(raw.mtime),
            generation: AtomicU32::new(raw.generation),
            extension: Extension::new(),
        }))
    }

    pub(super) fn new(fs: Arc<Ext4>, ino: u32) -> Arc<dyn Inode> {
        Self::try_new(fs, ino).expect("ext4 root inode must be readable")
    }

    fn read_raw(fs: &Ext4, ino: u32) -> Result<RawInode> {
        read_inode_from(fs.reader().as_ref(), fs.geometry(), ino)
            .map_err(|_| errno!(EIO, "failed to read ext4 inode"))
    }

    fn raw(&self) -> Result<RawInode> {
        let fs = self.fs()?;
        Self::read_raw(&fs, self.number)
    }

    fn refresh(&self, raw: &RawInode) {
        self.mode.store(raw.mode, Ordering::Release);
        self.uid.store(raw.uid, Ordering::Release);
        self.gid.store(raw.gid, Ordering::Release);
        self.size.store(raw.size, Ordering::Release);
        self.links.store(raw.links, Ordering::Release);
        self.blocks.store(raw.blocks, Ordering::Release);
        self.flags.store(raw.flags, Ordering::Release);
        self.atime.store(raw.atime, Ordering::Release);
        self.ctime.store(raw.ctime, Ordering::Release);
        self.mtime.store(raw.mtime, Ordering::Release);
        self.generation.store(raw.generation, Ordering::Release);
    }

    fn fs(&self) -> Result<Arc<Ext4>> {
        self.fs.upgrade().ok_or_else(|| errno!(EIO, "ext4 filesystem is gone"))
    }

    fn allocate_inode(&self, fs: &Ext4, type_: InodeType, mode: InodeMode) -> Result<u32> {
        let geom = fs.geometry();
        let group = 0usize;
        let bitmap = read_inode_bitmap_from(fs.reader().as_ref(), geom, group)
            .map_err(|_| errno!(EIO, "failed to read ext4 inode bitmap"))?;
        let mut allocator = BlockAllocator::from_bitmap(&bitmap, geom.inodes_per_group);
        let index = allocator
            .allocate()
            .ok_or_else(|| errno!(ENOSPC, "ext4 inodes exhausted"))?;
        let ino = (group as u32)
            .saturating_mul(geom.inodes_per_group as u32)
            .saturating_add(index as u32)
            .saturating_add(1);

        let offset = inode_offset_from(fs.reader().as_ref(), geom, ino)
            .map_err(|_| errno!(EIO, "new ext4 inode is out of range"))?;
        let mut raw = vec![0u8; geom.inode_size];
        let encoded_mode = mode.bits() | (type_ as u16);
        raw[0..2].copy_from_slice(&encoded_mode.to_le_bytes());
        raw[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
        let tree = &mut raw[0x28..0x28 + 60];
        tree[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        tree[4..6].copy_from_slice(&4u16.to_le_bytes());
        fs.reader()
            .write_at(offset, &raw)
            .ok_or_else(|| errno!(EIO, "failed to write ext4 inode"))?;

        let bitmap_offset = inode_bitmap_offset_from(fs.reader().as_ref(), geom, group)
            .map_err(|_| errno!(EIO, "failed to locate ext4 inode bitmap"))?;
        let mut updated = bitmap;
        let index = index as usize;
        if let Some(byte) = updated.get_mut(index / 8) {
            *byte |= 1 << (index % 8);
        }
        fs.reader()
            .write_at(bitmap_offset, &updated)
            .ok_or_else(|| errno!(EIO, "failed to update ext4 inode bitmap"))?;
        Ok(ino)
    }

    fn write_inode_data(fs: &Ext4, ino: u32, data: &[u8]) -> Result<()> {
        let raw = Self::read_raw(fs, ino)?;
        let (group, _) = inode_number_to_group(fs.geometry(), ino);
        let engine = WriteEngine::new(
            fs.reader().as_ref(),
            fs.reader().as_ref(),
            fs.geometry(),
            &raw,
            group,
        );
        engine
            .write_at(0, data)
            .map_err(|_| errno!(EIO, "failed to write ext4 inode data"))?;
        Ok(())
    }

    fn rewrite_dir(&self, fs: &Ext4, data: &[u8]) -> Result<()> {
        Self::write_inode_data(fs, self.number, data)?;
        self.refresh(&Self::read_raw(fs, self.number)?);
        Ok(())
    }

    fn adjust_links(fs: &Ext4, ino: u32, delta: i16) -> Result<()> {
        let geom = fs.geometry();
        let offset = inode_offset_from(fs.reader().as_ref(), geom, ino)
            .map_err(|_| errno!(EIO, "ext4 inode is out of range"))?;
        let mut raw = fs
            .reader()
            .read_at(offset, geom.inode_size)
            .ok_or_else(|| errno!(EIO, "failed to read ext4 inode"))?;
        let current = u16::from_le_bytes(
            raw.get(0x1A..0x1C)
                .ok_or_else(|| errno!(EIO, "short ext4 inode"))?
                .try_into()
                .unwrap(),
        );
        let updated = if delta < 0 {
            current.saturating_sub(delta.unsigned_abs())
        } else {
            current.saturating_add(delta as u16)
        };
        raw[0x1A..0x1C].copy_from_slice(&updated.to_le_bytes());
        fs.reader()
            .write_at(offset, &raw)
            .ok_or_else(|| errno!(EIO, "failed to update ext4 link count"))?;
        Ok(())
    }

    fn dirent_type(type_: InodeType) -> u8 {
        match type_ {
            InodeType::File => 1,
            InodeType::Dir => 2,
            InodeType::CharDevice => 3,
            InodeType::BlockDevice => 4,
            InodeType::NamedPipe => 5,
            InodeType::Socket => 6,
            InodeType::SymLink => 7,
            InodeType::Unknown => 0,
        }
    }

    fn read_all(&self) -> Result<Vec<u8>> {
        let fs = self.fs()?;
        let raw = Self::read_raw(&fs, self.number)?;
        read_file_from(fs.reader().as_ref(), fs.geometry(), &raw)
            .map_err(|_| errno!(EIO, "failed to read ext4 file data"))
    }

    fn file_type(&self) -> Result<InodeType> {
        InodeType::from_raw_mode(self.mode.load(Ordering::Acquire))
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

        let raw = Self::read_raw(&fs, self.number)?;
        let (group, _) = inode_number_to_group(fs.geometry(), self.number);
        let engine = WriteEngine::new(
            fs.reader().as_ref(),
            fs.reader().as_ref(),
            fs.geometry(),
            &raw,
            group,
        );
        let mut journal = vec![0u8; 8 * JOURNAL_BLOCK_SIZE];
        let result = engine.write_at_journaled_to(
            offset,
            &data,
            &mut journal,
            fs.reader().as_ref(),
            fs.journal_start(),
        );
        match result {
            Ok(()) => {
                self.refresh(&Self::read_raw(&fs, self.number)?);
                Ok(written)
            }
            Err(WriteError::NoSpace) => Err(errno!(ENOSPC, "ext4 journal or data space exhausted")),
            Err(WriteError::TooLarge) => Err(errno!(EINVAL, "ext4 write exceeds the supported size")),
            Err(_) => Err(errno!(EIO, "ext4 write failed")),
        }
    }

    fn readdir_at(&self, offset: usize, visitor: &mut dyn DirentVisitor) -> Result<usize> {
        let fs = self.fs()?;
        let raw = Self::read_raw(&fs, self.number)?;
        let entries: Vec<DirEntry> = read_dir_from(fs.reader().as_ref(), fs.geometry(), &raw)
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
        usize::try_from(self.size.load(Ordering::Acquire)).unwrap_or(usize::MAX)
    }

    fn resize(&self, _self_dentry: &Dentry, _new_size: usize) -> Result<()> {
        Err(errno!(EROFS, "ext4 mounts are read-only"))
    }

    fn metadata(&self) -> Result<Metadata> {
        let fs = self.fs()?;
        Ok(Metadata {
            ino: u64::from(self.number),
            size: self.size(),
            optimal_block_size: fs.geometry().block_size,
            nr_sectors_allocated: self.blocks.load(Ordering::Acquire) as usize * 2,
            last_access_at: Self::file_time(self.atime.load(Ordering::Acquire)),
            last_modify_at: Self::file_time(self.mtime.load(Ordering::Acquire)),
            last_meta_change_at: Self::file_time(self.ctime.load(Ordering::Acquire)),
            type_: self.file_type()?,
            mode: InodeMode::from_bits_truncate(self.mode.load(Ordering::Acquire)),
            nr_hard_links: self.links.load(Ordering::Acquire) as usize,
            uid: Uid::new(self.uid.load(Ordering::Acquire)),
            gid: Gid::new(self.gid.load(Ordering::Acquire)),
            container_dev_id: fs.device().id(),
            self_dev_id: None,
            birth_at: None,
        })
    }

    fn ino(&self) -> u64 {
        u64::from(self.number)
    }

    fn type_(&self) -> InodeType {
        self.file_type().unwrap_or(InodeType::Unknown)
    }

    fn mode(&self) -> Result<InodeMode> {
        Ok(InodeMode::from_bits_truncate(self.mode.load(Ordering::Acquire)))
    }

    fn set_mode(&self, _self_dentry: &Dentry, _mode: InodeMode) -> Result<()> {
        Err(errno!(EROFS, "ext4 mounts are read-only"))
    }

    fn owner(&self) -> Result<Uid> {
        Ok(Uid::new(self.uid.load(Ordering::Acquire)))
    }

    fn set_owner(&self, _self_dentry: &Dentry, _uid: Uid) -> Result<()> {
        Err(errno!(EROFS, "ext4 mounts are read-only"))
    }

    fn group(&self) -> Result<Gid> {
        Ok(Gid::new(self.gid.load(Ordering::Acquire)))
    }

    fn set_group(&self, _self_dentry: &Dentry, _gid: Gid) -> Result<()> {
        Err(errno!(EROFS, "ext4 mounts are read-only"))
    }

    fn atime(&self) -> FileTime {
        Self::file_time(self.atime.load(Ordering::Acquire))
    }

    fn set_atime(&self, _self_dentry: &Dentry, _time: FileTime) {}

    fn mtime(&self) -> FileTime {
        Self::file_time(self.mtime.load(Ordering::Acquire))
    }

    fn set_mtime(&self, _self_dentry: &Dentry, _time: FileTime) {}

    fn ctime(&self) -> FileTime {
        Self::file_time(self.ctime.load(Ordering::Acquire))
    }

    fn set_ctime(&self, _self_dentry: &Dentry, _time: FileTime) {}

    fn create(
        &self,
        _self_dentry: &Dentry,
        name: &str,
        type_: InodeType,
        mode: InodeMode,
    ) -> Result<Arc<dyn Inode>> {
        self.create_bytes(_self_dentry, name.as_bytes(), type_, mode)
    }

    fn create_bytes(
        &self,
        _self_dentry: &Dentry,
        name: &[u8],
        type_: InodeType,
        mode: InodeMode,
    ) -> Result<Arc<dyn Inode>> {
        if self.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let fs = self.fs()?;
        if !fs.writable() {
            return Err(errno!(EROFS, "ext4 mounts are read-only"));
        }
        let ino = self.allocate_inode(&fs, type_, mode)?;
        let block_size = fs.geometry().block_size;
        if type_ == InodeType::Dir {
            let mut initial = vec![0u8; block_size];
            initial = dir_edit::add(&initial, ino, b".", Self::dirent_type(InodeType::Dir), block_size)
                .map_err(|_| errno!(EIO, "failed to initialize ext4 directory"))?;
            initial = dir_edit::add(
                &initial,
                self.number,
                b"..",
                Self::dirent_type(InodeType::Dir),
                block_size,
            )
            .map_err(|_| errno!(EIO, "failed to initialize ext4 directory"))?;
            Self::write_inode_data(&fs, ino, &initial)?;
            Self::adjust_links(&fs, self.number, 1)?;
            self.refresh(&Self::read_raw(&fs, self.number)?);
        }
        let data = self.read_all()?;
        let updated = dir_edit::add(&data, ino, name, Self::dirent_type(type_), block_size)
            .map_err(|_| errno!(EIO, "failed to add ext4 directory entry"))?;
        self.rewrite_dir(&fs, &updated)?;
        Ext4Inode::try_new(fs, ino)
    }

    fn unlink(&self, child_dentry: &Dentry) -> Result<()> {
        if self.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let fs = self.fs()?;
        if !fs.writable() {
            return Err(errno!(EROFS, "ext4 mounts are read-only"));
        }
        let child = child_dentry
            .inode()
            .downcast_ref::<Ext4Inode>()
            .ok_or_else(|| errno!(EINVAL))?;
        aster_ext4::orphan::add(
            fs.reader().as_ref(),
            fs.reader().as_ref(),
            fs.geometry(),
            child.number,
        )
        .map_err(|_| errno!(EIO, "failed to add ext4 orphan"))?;
        let data = self.read_all()?;
        let updated = dir_edit::remove(&data, &child_dentry.name_bytes(), fs.geometry().block_size)
            .map_err(|_| errno!(ENOENT, "ext4 directory entry not found"))?;
        self.rewrite_dir(&fs, &updated)?;
        aster_ext4::orphan::remove(
            fs.reader().as_ref(),
            fs.reader().as_ref(),
            fs.geometry(),
            child.number,
        )
        .map_err(|_| errno!(EIO, "failed to remove ext4 orphan"))?;
        Ok(())
    }

    fn link_bytes(&self, _self_dentry: &Dentry, old_dentry: &Dentry, name: &[u8]) -> Result<()> {
        if self.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let fs = self.fs()?;
        if !fs.writable() {
            return Err(errno!(EROFS, "ext4 mounts are read-only"));
        }
        let old = old_dentry.inode().downcast_ref::<Ext4Inode>().ok_or_else(|| errno!(EINVAL))?;
        if old.type_() == InodeType::Dir {
            return Err(errno!(EPERM, "hard links to directories are not allowed"));
        }
        let data = self.read_all()?;
        let updated = dir_edit::add(&data, old.number, name, Self::dirent_type(old.type_()), fs.geometry().block_size)
            .map_err(|_| errno!(EEXIST, "ext4 directory entry already exists"))?;
        self.rewrite_dir(&fs, &updated)?;
        Self::adjust_links(&fs, old.number, 1)?;
        old.refresh(&Self::read_raw(&fs, old.number)?);
        Ok(())
    }

    fn rmdir(&self, child_dentry: &Dentry) -> Result<()> {
        if self.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let fs = self.fs()?;
        if !fs.writable() {
            return Err(errno!(EROFS, "ext4 mounts are read-only"));
        }
        let child = child_dentry
            .inode()
            .downcast_ref::<Ext4Inode>()
            .ok_or_else(|| errno!(EINVAL))?;
        if child.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let raw = Self::read_raw(&fs, child.number)?;
        let content = read_file_from(fs.reader().as_ref(), fs.geometry(), &raw)
            .map_err(|_| errno!(EIO, "failed to read ext4 directory"))?;
        if !dir_edit::is_empty(&content).map_err(|_| errno!(EIO, "corrupt ext4 directory"))? {
            return Err(errno!(ENOTEMPTY, "ext4 directory is not empty"));
        }
        let data = self.read_all()?;
        let updated = dir_edit::remove(&data, &child_dentry.name_bytes(), fs.geometry().block_size)
            .map_err(|_| errno!(ENOENT, "ext4 directory entry not found"))?;
        self.rewrite_dir(&fs, &updated)?;
        Self::adjust_links(&fs, self.number, -1)?;
        self.refresh(&Self::read_raw(&fs, self.number)?);
        Ok(())
    }

    fn rename_bytes(
        &self,
        old_child_dentry: &Dentry,
        new_dir_dentry: &Dentry,
        new_name: &[u8],
        replaced_inode: Option<&Arc<dyn Inode>>,
        mode: RenameMode,
    ) -> Result<()> {
        if mode == RenameMode::Exchange {
            return Err(errno!(EINVAL, "ext4 exchange rename is not supported"));
        }
        let fs = self.fs()?;
        if !fs.writable() {
            return Err(errno!(EROFS, "ext4 mounts are read-only"));
        }
        if self.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let new_dir = new_dir_dentry
            .inode()
            .downcast_ref::<Ext4Inode>()
            .ok_or_else(|| errno!(EINVAL))?;
        if new_dir.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let child = old_child_dentry
            .inode()
            .downcast_ref::<Ext4Inode>()
            .ok_or_else(|| errno!(EINVAL))?;
        if child.number == new_dir.number || child.number == self.number {
            return Err(errno!(EINVAL, "cannot rename a directory into itself"));
        }

        let old_name = old_child_dentry.name_bytes();
        if replaced_inode.is_some() {
            if child.type_() == InodeType::Dir {
                return Err(errno!(ENOTDIR));
            }
            let new_data = new_dir.read_all()?;
            let replaced = dir_edit::remove(&new_data, new_name, fs.geometry().block_size)
                .map_err(|_| errno!(ENOENT))?;
            new_dir.rewrite_dir(&fs, &replaced)?;
        }

        if self.number == new_dir.number {
            let data = self.read_all()?;
            let renamed = if old_name == new_name {
                data
            } else {
                dir_edit::rename_entry(&data, child.number, new_name, fs.geometry().block_size)
                    .map_err(|_| errno!(EEXIST, "ext4 directory entry already exists"))?
            };
            self.rewrite_dir(&fs, &renamed)?;
        } else {
            if child.type_() == InodeType::Dir {
                let parent = u32::try_from(new_dir.number).map_err(|_| errno!(EINVAL))?;
                let child_data = child.read_all()?;
                let without_parent =
                    dir_edit::remove(&child_data, b"..", fs.geometry().block_size)
                        .map_err(|_| errno!(EIO, "corrupt ext4 directory"))?;
                let updated_child = dir_edit::add(
                    &without_parent,
                    parent,
                    b"..",
                    Self::dirent_type(InodeType::Dir),
                    fs.geometry().block_size,
                )
                .map_err(|_| errno!(EIO, "failed to update ext4 parent entry"))?;
                Self::write_inode_data(&fs, child.number, &updated_child)?;
            }

            let old_data = self.read_all()?;
            let removed = dir_edit::remove(&old_data, &old_name, fs.geometry().block_size)
                .map_err(|_| errno!(ENOENT, "ext4 directory entry not found"))?;
            self.rewrite_dir(&fs, &removed)?;
            let new_data = new_dir.read_all()?;
            let added = dir_edit::add(
                &new_data,
                child.number,
                new_name,
                Self::dirent_type(child.type_()),
                fs.geometry().block_size,
            )
            .map_err(|_| errno!(EEXIST, "ext4 directory entry already exists"))?;
            new_dir.rewrite_dir(&fs, &added)?;
            if child.type_() == InodeType::Dir {
                Self::adjust_links(&fs, self.number, -1)?;
                Self::adjust_links(&fs, new_dir.number, 1)?;
                self.refresh(&Self::read_raw(&fs, self.number)?);
                new_dir.refresh(&Self::read_raw(&fs, new_dir.number)?);
            }
        }
        Ok(())
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        self.lookup_bytes(name.as_bytes())
    }

    fn lookup_bytes(&self, name: &[u8]) -> Result<Arc<dyn Inode>> {
        if self.type_() != InodeType::Dir {
            return Err(errno!(ENOTDIR));
        }
        let fs = self.fs()?;
        let raw = Self::read_raw(&fs, self.number)?;
        let ino = lookup_from(fs.reader().as_ref(), fs.geometry(), &raw, name)
            .ok_or_else(|| errno!(ENOENT, "no such ext4 directory entry"))?;
        Ext4Inode::try_new(fs, ino)
    }

    fn read_link(&self) -> Result<SymbolicLink> {
        if self.type_() != InodeType::SymLink {
            return Err(errno!(EINVAL, "not a symbolic link"));
        }
        let raw = self.raw()?;
        if let Some(target) = fast_symlink(&raw) {
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
