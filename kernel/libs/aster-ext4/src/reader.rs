// SPDX-License-Identifier: MPL-2.0

//! Bounded read-only inode and extent-tree access for clean ext4 images.
//!
//! All reads go through the [`BlockReader`] trait so the same logic serves a
//! whole-image byte slice in host tests and an on-demand block device in the
//! kernel. The reader walks the extent tree, materializes holes as zeros and
//! treats unwritten extents as zeros, then truncates to the inode's size.

extern crate alloc;

use alloc::{vec, vec::Vec};

use crate::SUPER_BLOCK_OFFSET;

pub const EXTENT_MAGIC: u16 = 0xF30A;
pub const EXTENT_HEADER_LEN: usize = 12;
pub const EXTENT_ENTRY_LEN: usize = 12;
pub const INODE_BLOCK_PTRS_OFFSET: usize = 0x28;
pub const INODE_BLOCK_PTRS_LEN: usize = 60;
pub const UNWRITTEN_EXTENT: u16 = 0x8000;
pub const ROOT_INO: u32 = 2;
const MAX_EXTENT_ENTRIES: usize = 256;

/// A bounded source of ext4 metadata and data bytes.
///
/// The kernel implements this over its block device; host tests use
/// [`SliceReader`]. A failed read is reported as `None` so no caller can
/// observe bytes outside the requested range.
pub trait BlockReader {
    fn read_at(&self, offset: u64, len: usize) -> Option<Vec<u8>>;
}

/// A bounded destination for ext4 metadata and data bytes.
pub trait BlockWriter {
    fn write_at(&self, offset: u64, data: &[u8]) -> Option<()>;
}

pub struct SliceReader<'a>(&'a [u8]);

impl<'a> SliceReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self(data)
    }
}

impl BlockReader for SliceReader<'_> {
    fn read_at(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(len)?;
        Some(self.0.get(start..end)?.to_vec())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderError {
    Truncated,
    BadExtentMagic,
    ExtentLimitExceeded,
    InodeOutOfRange,
    BadBlockSize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub block_size: usize,
    pub blocks_count: u64,
    pub inodes_per_group: usize,
    pub inode_size: usize,
    pub blocks_per_group: usize,
    pub group_desc_size: usize,
    pub group_desc_table: usize,
}

impl Geometry {
    /// Number of blocks that actually exist in a group, excluding the
    /// unused tail of the on-disk bitmap beyond the device capacity.
    pub fn usable_blocks(&self, group: usize) -> usize {
        let start = (group as u64).saturating_mul(self.blocks_per_group as u64);
        let available = self.blocks_count.saturating_sub(start);
        usize::try_from(available)
            .unwrap_or(usize::MAX)
            .min(self.blocks_per_group)
    }
}

fn le_u16(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .map(u16::from_le_bytes)
}

fn le_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
}

pub fn geometry_from(reader: &dyn BlockReader) -> Result<Geometry, ReaderError> {
    let sb = reader
        .read_at(SUPER_BLOCK_OFFSET as u64, 1024)
        .ok_or(ReaderError::Truncated)?;
    let log_block_size = le_u32(&sb, 0x18).ok_or(ReaderError::Truncated)?;
    if log_block_size > 6 {
        return Err(ReaderError::BadBlockSize);
    }
    let block_size = 1024usize << log_block_size;
    let blocks_count_lo = le_u32(&sb, 0x04).ok_or(ReaderError::Truncated)? as u64;
    let blocks_count_hi = if le_u32(&sb, 0x60).ok_or(ReaderError::Truncated)? & (1 << 7) != 0 {
        le_u32(&sb, 0x150).ok_or(ReaderError::Truncated)? as u64
    } else {
        0
    };
    let blocks_count = blocks_count_lo | (blocks_count_hi << 32);
    let inodes_per_group = le_u32(&sb, 0x28).ok_or(ReaderError::Truncated)? as usize;
    let inode_size = le_u16(&sb, 0x58).ok_or(ReaderError::Truncated)? as usize;
    let blocks_per_group = le_u32(&sb, 0x20).ok_or(ReaderError::Truncated)? as usize;
    if block_size == 0 || inodes_per_group == 0 || inode_size < 128 || blocks_per_group == 0 {
        return Err(ReaderError::BadBlockSize);
    }
    let group_desc_table = block_size * ((1024 + 1024 + block_size - 1) / block_size);
    Ok(Geometry {
        block_size,
        blocks_count,
        inodes_per_group,
        inode_size,
        blocks_per_group,
        group_desc_size: 64,
        group_desc_table,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inode {
    pub number: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub links: u16,
    pub blocks: u32,
    pub flags: u32,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub generation: u32,
    pub block_ptrs: [u8; INODE_BLOCK_PTRS_LEN],
}

pub fn inode_number_to_group(geom: &Geometry, ino: u32) -> (usize, usize) {
    let zero_based = (ino - 1) as usize;
    (zero_based / geom.inodes_per_group, zero_based % geom.inodes_per_group)
}

/// Byte offset of an inode's raw record on the device.
pub fn inode_offset_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    ino: u32,
) -> Result<u64, ReaderError> {
    if ino == 0 {
        return Err(ReaderError::InodeOutOfRange);
    }
    let (group, index) = inode_number_to_group(geom, ino);
    let desc_start = geom
        .group_desc_table
        .checked_add(
            group
                .checked_mul(geom.group_desc_size)
                .ok_or(ReaderError::Truncated)?,
        )
        .ok_or(ReaderError::Truncated)?;
    let desc = reader
        .read_at(desc_start as u64, geom.group_desc_size)
        .ok_or(ReaderError::Truncated)?;
    let table = le_u32(&desc, 0x08).ok_or(ReaderError::Truncated)? as u64;
    table
        .checked_mul(geom.block_size as u64)
        .and_then(|base| base.checked_add((index * geom.inode_size) as u64))
        .ok_or(ReaderError::Truncated)
}

pub fn read_inode_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    ino: u32,
) -> Result<Inode, ReaderError> {
    if ino == 0 {
        return Err(ReaderError::InodeOutOfRange);
    }
    let (group, index) = inode_number_to_group(geom, ino);
    let desc_offset = group
        .checked_mul(geom.group_desc_size)
        .ok_or(ReaderError::Truncated)?;
    let desc_start = geom
        .group_desc_table
        .checked_add(desc_offset)
        .ok_or(ReaderError::Truncated)?;
    let desc = reader
        .read_at(desc_start as u64, geom.group_desc_size)
        .ok_or(ReaderError::Truncated)?;
    let inode_table = le_u32(&desc, 0x08).ok_or(ReaderError::Truncated)? as usize;
    let offset = inode_table
        .checked_mul(geom.block_size)
        .and_then(|base| base.checked_add(index.checked_mul(geom.inode_size)?))
        .ok_or(ReaderError::Truncated)?;
    let raw = reader
        .read_at(offset as u64, geom.inode_size)
        .ok_or(ReaderError::Truncated)?;
    let mut block_ptrs = [0u8; INODE_BLOCK_PTRS_LEN];
    block_ptrs.copy_from_slice(
        &raw[INODE_BLOCK_PTRS_OFFSET..INODE_BLOCK_PTRS_OFFSET + INODE_BLOCK_PTRS_LEN],
    );
    let size_lo = le_u32(&raw, 0x04).ok_or(ReaderError::Truncated)? as u64;
    let size_hi = le_u32(&raw, 0x6C).ok_or(ReaderError::Truncated)? as u64;
    Ok(Inode {
        number: ino,
        mode: le_u16(&raw, 0x00).ok_or(ReaderError::Truncated)?,
        uid: le_u16(&raw, 0x02).ok_or(ReaderError::Truncated)? as u32,
        gid: le_u16(&raw, 0x18).ok_or(ReaderError::Truncated)? as u32,
        size: size_lo | (size_hi << 32),
        links: le_u16(&raw, 0x1A).ok_or(ReaderError::Truncated)?,
        blocks: le_u32(&raw, 0x1C).ok_or(ReaderError::Truncated)?,
        flags: le_u32(&raw, 0x20).ok_or(ReaderError::Truncated)?,
        atime: le_u32(&raw, 0x08).ok_or(ReaderError::Truncated)?,
        ctime: le_u32(&raw, 0x0C).ok_or(ReaderError::Truncated)?,
        mtime: le_u32(&raw, 0x10).ok_or(ReaderError::Truncated)?,
        generation: le_u32(&raw, 0x64).ok_or(ReaderError::Truncated)?,
        block_ptrs,
    })
}

/// Byte offset of a group's block-allocation bitmap.
pub fn block_bitmap_offset_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    group: usize,
) -> Result<u64, ReaderError> {
    let desc_offset = group
        .checked_mul(geom.group_desc_size)
        .ok_or(ReaderError::Truncated)?;
    let desc_start = geom
        .group_desc_table
        .checked_add(desc_offset)
        .ok_or(ReaderError::Truncated)?;
    let desc = reader
        .read_at(desc_start as u64, geom.group_desc_size)
        .ok_or(ReaderError::Truncated)?;
    let bitmap_block = le_u32(&desc, 0x00).ok_or(ReaderError::Truncated)? as u64;
    bitmap_block
        .checked_mul(geom.block_size as u64)
        .ok_or(ReaderError::Truncated)
}

/// Byte offset of a group's inode-allocation bitmap.
pub fn inode_bitmap_offset_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    group: usize,
) -> Result<u64, ReaderError> {
    let desc_start = geom
        .group_desc_table
        .checked_add(
            group
                .checked_mul(geom.group_desc_size)
                .ok_or(ReaderError::Truncated)?,
        )
        .ok_or(ReaderError::Truncated)?;
    let desc = reader
        .read_at(desc_start as u64, geom.group_desc_size)
        .ok_or(ReaderError::Truncated)?;
    let bitmap_block = le_u32(&desc, 0x04).ok_or(ReaderError::Truncated)? as u64;
    bitmap_block
        .checked_mul(geom.block_size as u64)
        .ok_or(ReaderError::Truncated)
}

/// Reads the inode-allocation bitmap for a group.
pub fn read_inode_bitmap_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    group: usize,
) -> Result<Vec<u8>, ReaderError> {
    let start = inode_bitmap_offset_from(reader, geom, group)?;
    reader
        .read_at(start, geom.block_size)
        .ok_or(ReaderError::Truncated)
}

/// Reads the block-allocation bitmap for a group.
pub fn read_block_bitmap_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    group: usize,
) -> Result<Vec<u8>, ReaderError> {
    let start = block_bitmap_offset_from(reader, geom, group)?;
    reader
        .read_at(start, geom.block_size)
        .ok_or(ReaderError::Truncated)
}

pub fn read_block_bitmap(image: &[u8], geom: &Geometry, group: usize) -> Result<Vec<u8>, ReaderError> {
    read_block_bitmap_from(&SliceReader::new(image), geom, group)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extent {
    pub logical_block: u64,
    pub physical_block: u64,
    pub len: u16,
    pub unwritten: bool,
}

fn parse_extent_body(body: &[u8], depth: u16) -> Result<(Vec<Extent>, Vec<(u64, u64)>), ReaderError> {
    if body.len() < EXTENT_HEADER_LEN {
        return Err(ReaderError::Truncated);
    }
    if le_u16(body, 0x00).ok_or(ReaderError::Truncated)? != EXTENT_MAGIC {
        return Err(ReaderError::BadExtentMagic);
    }
    let entries = le_u16(body, 0x02).ok_or(ReaderError::Truncated)? as usize;
    if entries > MAX_EXTENT_ENTRIES {
        return Err(ReaderError::ExtentLimitExceeded);
    }
    let mut extents = Vec::new();
    let mut indices = Vec::new();
    for index in 0..entries {
        let offset = EXTENT_HEADER_LEN + index * EXTENT_ENTRY_LEN;
        let entry = body
            .get(offset..offset + EXTENT_ENTRY_LEN)
            .ok_or(ReaderError::Truncated)?;
        let logical = le_u32(entry, 0x00).ok_or(ReaderError::Truncated)? as u64;
        if depth == 0 {
            let raw_len = le_u16(entry, 0x04).ok_or(ReaderError::Truncated)?;
            let unwritten = raw_len & UNWRITTEN_EXTENT != 0;
            let len = if unwritten { raw_len & !UNWRITTEN_EXTENT } else { raw_len };
            let start_hi = le_u16(entry, 0x06).ok_or(ReaderError::Truncated)? as u64;
            let start_lo = le_u32(entry, 0x08).ok_or(ReaderError::Truncated)? as u64;
            extents.push(Extent {
                logical_block: logical,
                physical_block: (start_hi << 32) | start_lo,
                len,
                unwritten,
            });
        } else {
            let leaf_lo = le_u32(entry, 0x04).ok_or(ReaderError::Truncated)? as u64;
            let leaf_hi = le_u16(entry, 0x08).ok_or(ReaderError::Truncated)? as u64;
            indices.push((logical, (leaf_hi << 32) | leaf_lo));
        }
    }
    Ok((extents, indices))
}

pub fn extent_tree_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    inode: &Inode,
) -> Result<Vec<Extent>, ReaderError> {
    let mut extents = Vec::new();
    let mut queue = Vec::new();
    let (root_extents, root_indices) = parse_extent_body(&inode.block_ptrs, 0)?;
    extents.extend(root_extents);
    queue.extend(root_indices);

    while let Some((_logical, block)) = queue.pop() {
        if queue.len() > MAX_EXTENT_ENTRIES {
            return Err(ReaderError::ExtentLimitExceeded);
        }
        let start = block
            .checked_mul(geom.block_size as u64)
            .ok_or(ReaderError::Truncated)?;
        let node = reader
            .read_at(start, geom.block_size)
            .ok_or(ReaderError::Truncated)?;
        let (found, deeper) = parse_extent_body(&node, 0)?;
        extents.extend(found);
        queue.extend(deeper);
        if queue.len() > MAX_EXTENT_ENTRIES {
            return Err(ReaderError::ExtentLimitExceeded);
        }
    }
    extents.sort_by_key(|item| item.logical_block);
    Ok(extents)
}

/// Reads file data, materializing holes and unwritten extents as zeros.
pub fn read_file_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    inode: &Inode,
) -> Result<Vec<u8>, ReaderError> {
    if inode.flags & 0x1000_0000 != 0 {
        return Err(ReaderError::BadBlockSize);
    }
    let size = usize::try_from(inode.size).map_err(|_| ReaderError::Truncated)?;
    let mut data = vec![0u8; size];
    let block_size = geom.block_size;
    for extent in extent_tree_from(reader, geom, inode)? {
        if extent.unwritten {
            continue;
        }
        let logical = usize::try_from(extent.logical_block)
            .map_err(|_| ReaderError::Truncated)?
            .checked_mul(block_size)
            .ok_or(ReaderError::Truncated)?;
        let physical = extent
            .physical_block
            .checked_mul(block_size as u64)
            .ok_or(ReaderError::Truncated)?;
        let len = extent.len as usize;
        for block in 0..len {
            let block_offset = block
                .checked_mul(block_size)
                .ok_or(ReaderError::Truncated)?;
            let dst = logical
                .checked_add(block_offset)
                .ok_or(ReaderError::Truncated)?;
            if dst >= size {
                break;
            }
            let src = physical
                .checked_add(block_offset as u64)
                .ok_or(ReaderError::Truncated)?;
            let chunk = reader
                .read_at(src, block_size)
                .ok_or(ReaderError::Truncated)?;
            let out = &mut data[dst..size.min(dst + block_size)];
            out.copy_from_slice(&chunk[..out.len()]);
        }
    }
    Ok(data)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiskEntryType {
    Unknown,
    File,
    Dir,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Symlink,
}

impl DiskEntryType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::File,
            2 => Self::Dir,
            3 => Self::CharDevice,
            4 => Self::BlockDevice,
            5 => Self::Fifo,
            6 => Self::Socket,
            7 => Self::Symlink,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    pub ino: u32,
    pub name: Vec<u8>,
    pub file_type: DiskEntryType,
}

/// Parses linear directory entries from a directory's data blocks.
pub fn read_dir_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    inode: &Inode,
) -> Result<Vec<DirEntry>, ReaderError> {
    let data = read_file_from(reader, geom, inode)?;
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    while cursor + 8 <= data.len() {
        let ino = le_u32(&data, cursor).ok_or(ReaderError::Truncated)?;
        let rec_len = le_u16(&data, cursor + 4).ok_or(ReaderError::Truncated)? as usize;
        if rec_len < 8 || cursor + rec_len > data.len() {
            return Err(ReaderError::Truncated);
        }
        let name_len = data[cursor + 6] as usize;
        let file_type = data[cursor + 7];
        if name_len + 8 > rec_len {
            return Err(ReaderError::Truncated);
        }
        if ino != 0 {
            entries.push(DirEntry {
                ino,
                name: data[cursor + 8..cursor + 8 + name_len].to_vec(),
                file_type: DiskEntryType::from_u8(file_type),
            });
        }
        cursor += rec_len;
    }
    Ok(entries)
}

pub fn lookup_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    dir: &Inode,
    name: &[u8],
) -> Option<u32> {
    read_dir_from(reader, geom, dir)
        .ok()?
        .into_iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.ino)
}

/// Reads a fast symlink target stored inline in the inode's block pointers.
pub fn fast_symlink(inode: &Inode) -> Option<Vec<u8>> {
    if inode.size as usize > INODE_BLOCK_PTRS_LEN || inode.size == 0 {
        return None;
    }
    if inode.mode & 0xF000 != 0xA000 {
        return None;
    }
    Some(inode.block_ptrs[..inode.size as usize].to_vec())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XattrEntry {
    pub name_index: u8,
    pub name_len: u8,
    pub value_len: u16,
}

pub fn xattr_entries(block: &[u8]) -> Result<Vec<XattrEntry>, ReaderError> {
    if block.len() < 32 {
        return Err(ReaderError::Truncated);
    }
    let magic = le_u32(block, 0x00).ok_or(ReaderError::Truncated)?;
    if magic != 0xEA02_0000 {
        return Err(ReaderError::BadExtentMagic);
    }
    let mut cursor = 32usize;
    let mut entries = Vec::new();
    while cursor + 8 <= block.len() {
        let name_len = block[cursor] as usize;
        let name_index = block[cursor + 1];
        let value_len = le_u16(block, cursor + 2).ok_or(ReaderError::Truncated)? as usize;
        let entry_len = 8 + ((name_len + 3) & !3) + ((value_len + 3) & !3);
        if entry_len < 8 || cursor + entry_len > block.len() {
            return Err(ReaderError::Truncated);
        }
        entries.push(XattrEntry {
            name_index,
            name_len: name_len as u8,
            value_len: value_len as u16,
        });
        cursor += entry_len;
    }
    Ok(entries)
}

// Slice convenience wrappers retained for host tests and simple callers.
pub fn geometry(image: &[u8]) -> Result<Geometry, ReaderError> {
    geometry_from(&SliceReader::new(image))
}

pub fn read_inode(image: &[u8], geom: &Geometry, ino: u32) -> Result<Inode, ReaderError> {
    read_inode_from(&SliceReader::new(image), geom, ino)
}

pub fn extent_tree(image: &[u8], geom: &Geometry, inode: &Inode) -> Result<Vec<Extent>, ReaderError> {
    extent_tree_from(&SliceReader::new(image), geom, inode)
}

pub fn read_file(image: &[u8], geom: &Geometry, inode: &Inode) -> Result<Vec<u8>, ReaderError> {
    read_file_from(&SliceReader::new(image), geom, inode)
}

pub fn read_dir(image: &[u8], geom: &Geometry, inode: &Inode) -> Result<Vec<DirEntry>, ReaderError> {
    read_dir_from(&SliceReader::new(image), geom, inode)
}

pub fn lookup(image: &[u8], geom: &Geometry, dir: &Inode, name: &[u8]) -> Option<u32> {
    lookup_from(&SliceReader::new(image), geom, dir, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn fixture(name: &str) -> Vec<u8> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.pop();
        path.push("target/qualification/inputs/ext4");
        path.push(format!("{name}.ext4"));
        fs::read(path).unwrap()
    }

    #[test]
    fn device_reader_matches_slice_reader() {
        let image = fixture("basic");
        let slice_geom = geometry(&image).unwrap();
        let device_geom = geometry_from(&SliceReader::new(&image)).unwrap();
        assert_eq!(slice_geom, device_geom);

        let root = read_inode_from(&SliceReader::new(&image), &device_geom, ROOT_INO).unwrap();
        let expected = read_inode(&image, &slice_geom, ROOT_INO).unwrap();
        assert_eq!(root, expected);

        let tree = extent_tree_from(&SliceReader::new(&image), &device_geom, &root).unwrap();
        assert_eq!(tree, extent_tree(&image, &slice_geom, &root).unwrap());

        let data = read_file_from(&SliceReader::new(&image), &device_geom, &root).unwrap();
        assert_eq!(data, read_file(&image, &slice_geom, &root).unwrap());
    }

    #[test]
    fn reads_root_inode_and_extent_tree() {
        let image = fixture("basic");
        let geom = geometry(&image).unwrap();
        let root = read_inode(&image, &geom, ROOT_INO).unwrap();
        assert_eq!(root.mode & 0xF000, 0x4000);
        let extents = extent_tree(&image, &geom, &root).unwrap();
        assert!(!extents.is_empty());
    }

    #[test]
    fn reads_marker_file_content() {
        let image = fixture("basic");
        let geom = geometry(&image).unwrap();
        let root = read_inode(&image, &geom, ROOT_INO).unwrap();
        let data = read_file(&image, &geom, &root).unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn sparse_fixture_reads_without_error() {
        let image = fixture("sparse");
        let geom = geometry(&image).unwrap();
        let root = read_inode(&image, &geom, ROOT_INO).unwrap();
        let _ = read_file(&image, &geom, &root).unwrap();
    }

    #[test]
    fn reads_root_directory_and_finds_marker() {
        let image = fixture("basic");
        let geom = geometry(&image).unwrap();
        let root = read_inode(&image, &geom, ROOT_INO).unwrap();
        let entries = read_dir(&image, &geom, &root).unwrap();
        assert!(entries.iter().any(|entry| entry.name == b"marker.txt"));
        let ino = lookup(&image, &geom, &root, b"marker.txt").unwrap();
        let marker = read_inode(&image, &geom, ino).unwrap();
        let data = read_file(&image, &geom, &marker).unwrap();
        assert_eq!(data, b"lc14-basic\n");
    }

    #[test]
    fn xattr_parser_rejects_bad_magic() {
        let mut block = vec![0u8; 64];
        assert_eq!(xattr_entries(&block), Err(ReaderError::BadExtentMagic));
        block[0..4].copy_from_slice(&0xEA02_0000u32.to_le_bytes());
        assert!(xattr_entries(&block).is_ok());
    }
}
