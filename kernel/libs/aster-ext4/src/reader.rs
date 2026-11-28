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
pub const INODE_EXTENTS_FLAG: u32 = 0x0008_0000;
pub const ROOT_INO: u32 = 2;
const MAX_EXTENT_DEPTH: u16 = 5;
const MAX_EXTENT_NODES: usize = 256;

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
    BadExtentDepth,
    BadExtentRange,
    ExtentLimitExceeded,
    InodeOutOfRange,
    BadBlockSize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub block_size: usize,
    pub blocks_count: u64,
    pub first_data_block: u64,
    pub inodes_count: u32,
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
        let start = (group as u64)
            .saturating_mul(self.blocks_per_group as u64)
            .saturating_add(self.first_data_block);
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
    let incompat = le_u32(&sb, 0x60).ok_or(ReaderError::Truncated)?;
    let blocks_count_hi = if incompat & crate::INCOMPAT_64BIT != 0 {
        le_u32(&sb, 0x150).ok_or(ReaderError::Truncated)? as u64
    } else {
        0
    };
    let blocks_count = blocks_count_lo | (blocks_count_hi << 32);
    let first_data_block = u64::from(le_u32(&sb, 0x14).ok_or(ReaderError::Truncated)?);
    let inodes_count = le_u32(&sb, 0).ok_or(ReaderError::Truncated)?;
    let inodes_per_group = le_u32(&sb, 0x28).ok_or(ReaderError::Truncated)? as usize;
    let inode_size = le_u16(&sb, 0x58).ok_or(ReaderError::Truncated)? as usize;
    let blocks_per_group = le_u32(&sb, 0x20).ok_or(ReaderError::Truncated)? as usize;
    if inodes_per_group == 0 || inode_size < 128 || inode_size > block_size
        || blocks_per_group == 0 || first_data_block >= blocks_count
    {
        return Err(ReaderError::BadBlockSize);
    }
    let group_desc_table = block_size * ((1024 + 1024 + block_size - 1) / block_size);
    Ok(Geometry {
        block_size,
        blocks_count,
        first_data_block,
        inodes_count,
        inodes_per_group,
        inode_size,
        blocks_per_group,
        group_desc_size: crate::descriptor_size(&sb, incompat, block_size)
            .map_err(|_| ReaderError::BadBlockSize)?,
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
    if ino == 0 || ino > geom.inodes_count {
        return Err(ReaderError::InodeOutOfRange);
    }
    let (group, index) = inode_number_to_group(geom, ino);
    let within_table = index.checked_mul(geom.inode_size).ok_or(ReaderError::Truncated)?;
    let offset = group_metadata_offset(reader, geom, group, 0x08)?
        .checked_add(within_table as u64)
        .ok_or(ReaderError::Truncated)?;
    let device_len = geom.blocks_count.checked_mul(geom.block_size as u64)
        .ok_or(ReaderError::Truncated)?;
    if offset.checked_add(geom.inode_size as u64).is_none_or(|end| end > device_len) {
        return Err(ReaderError::InodeOutOfRange);
    }
    Ok(offset)
}

pub fn read_inode_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    ino: u32,
) -> Result<Inode, ReaderError> {
    let offset = inode_offset_from(reader, geom, ino)?;
    let raw = reader
        .read_at(offset, geom.inode_size)
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
    group_metadata_offset(reader, geom, group, 0x00)
}

/// Byte offset of a group's inode-allocation bitmap.
pub fn inode_bitmap_offset_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    group: usize,
) -> Result<u64, ReaderError> {
    group_metadata_offset(reader, geom, group, 0x04)
}

fn group_metadata_offset(
    reader: &dyn BlockReader,
    geom: &Geometry,
    group: usize,
    field_offset: usize,
) -> Result<u64, ReaderError> {
    if geom.usable_blocks(group) == 0 {
        return Err(ReaderError::Truncated);
    }
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
    let lo = u64::from(le_u32(&desc, field_offset).ok_or(ReaderError::Truncated)?);
    let hi = if geom.group_desc_size >= crate::GROUP_DESC_SIZE_64 {
        u64::from(le_u32(&desc, field_offset + 0x20).ok_or(ReaderError::Truncated)?)
    } else {
        0
    };
    let block = lo | (hi << 32);
    if block <= geom.first_data_block || block >= geom.blocks_count {
        return Err(ReaderError::Truncated);
    }
    block
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

fn parse_extent_body(body: &[u8], depth: u16) -> Result<(Vec<Extent>, Vec<u64>), ReaderError> {
    if body.len() < EXTENT_HEADER_LEN {
        return Err(ReaderError::Truncated);
    }
    if le_u16(body, 0x00).ok_or(ReaderError::Truncated)? != EXTENT_MAGIC {
        return Err(ReaderError::BadExtentMagic);
    }
    if le_u16(body, 0x06) != Some(depth) || depth > MAX_EXTENT_DEPTH {
        return Err(ReaderError::BadExtentDepth);
    }
    let entries = le_u16(body, 0x02).ok_or(ReaderError::Truncated)? as usize;
    let capacity = le_u16(body, 0x04).ok_or(ReaderError::Truncated)? as usize;
    if entries > capacity || capacity > (body.len() - EXTENT_HEADER_LEN) / EXTENT_ENTRY_LEN {
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
            let unwritten = raw_len > UNWRITTEN_EXTENT;
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
            indices.push((leaf_hi << 32) | leaf_lo);
        }
    }
    Ok((extents, indices))
}

pub fn extent_tree_from(
    reader: &dyn BlockReader,
    geom: &Geometry,
    inode: &Inode,
) -> Result<Vec<Extent>, ReaderError> {
    if inode.flags & INODE_EXTENTS_FLAG == 0 {
        return Err(ReaderError::BadExtentMagic);
    }
    let depth = le_u16(&inode.block_ptrs, 0x06).ok_or(ReaderError::Truncated)?;
    let (mut extents, children) = parse_extent_body(&inode.block_ptrs, depth)?;
    let mut queue: Vec<_> = children.into_iter().map(|block| (block, depth - 1)).collect();
    let mut nodes_read = 0;

    while let Some((block, depth)) = queue.pop() {
        nodes_read += 1;
        if nodes_read + queue.len() > MAX_EXTENT_NODES {
            return Err(ReaderError::ExtentLimitExceeded);
        }
        if block == 0 || block >= geom.blocks_count {
            return Err(ReaderError::BadExtentRange);
        }
        let start = block
            .checked_mul(geom.block_size as u64)
            .ok_or(ReaderError::Truncated)?;
        let node = reader
            .read_at(start, geom.block_size)
            .ok_or(ReaderError::Truncated)?;
        let (found, deeper) = parse_extent_body(&node, depth)?;
        extents.extend(found);
        queue.extend(deeper.into_iter().map(|child| (child, depth - 1)));
    }
    extents.sort_by_key(|item| item.logical_block);
    let mut end = 0;
    for extent in &extents {
        if extent.len == 0 || extent.logical_block < end
            || extent.physical_block == 0
            || extent.physical_block + u64::from(extent.len) > geom.blocks_count
        {
            return Err(ReaderError::BadExtentRange);
        }
        end = extent.logical_block + u64::from(extent.len);
    }
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
    fn reads_depth_one_extents_from_mkfs() {
        let image = fixture("fragmented");
        let geom = geometry(&image).unwrap();
        let root = read_inode(&image, &geom, ROOT_INO).unwrap();
        let ino = lookup(&image, &geom, &root, b"extents.bin").unwrap();
        let inode = read_inode(&image, &geom, ino).unwrap();
        assert_eq!(le_u16(&inode.block_ptrs, 0x06), Some(1));
        let data = read_file(&image, &geom, &inode).unwrap();
        let mut expected = vec![0; 8 * geom.block_size + 1];
        for block in [0, 2, 4, 6, 8] {
            expected[block * geom.block_size] = b'0' + block as u8;
        }
        assert_eq!(data, expected);
    }

    #[test]
    fn descriptor_addresses_keep_their_high_word() {
        let mut image = fixture("large-address");
        let mut geom = geometry(&image).unwrap();
        geom.blocks_count = 1 << 33;
        let table = geom.group_desc_table;
        image[table + 0x20..table + 0x24].copy_from_slice(&1u32.to_le_bytes());
        image[table + 0x28..table + 0x2C].copy_from_slice(&1u32.to_le_bytes());
        let bitmap_lo = u64::from(le_u32(&image, table).unwrap());
        let inode_table_lo = u64::from(le_u32(&image, table + 8).unwrap());
        let reader = SliceReader::new(&image);
        assert_eq!(block_bitmap_offset_from(&reader, &geom, 0), Ok((bitmap_lo + (1 << 32)) * 4096));
        assert_eq!(inode_offset_from(&reader, &geom, 1), Ok((inode_table_lo + (1 << 32)) * 4096));
        assert_eq!(inode_offset_from(&reader, &geom, geom.inodes_count + 1), Err(ReaderError::InodeOutOfRange));
    }

    #[test]
    fn inode_record_cannot_extend_past_the_volume() {
        let mut image = fixture("basic");
        let geom = geometry(&image).unwrap();
        let field = geom.group_desc_table + 8;
        image[field..field + 4].copy_from_slice(&((geom.blocks_count - 1) as u32).to_le_bytes());
        let ino = u32::try_from(geom.block_size / geom.inode_size + 1).unwrap();
        assert_eq!(inode_offset_from(&SliceReader::new(&image), &geom, ino), Err(ReaderError::InodeOutOfRange));
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

}
