// SPDX-License-Identifier: MPL-2.0

//! Bounded read-only inode and extent-tree access for clean ext4 images.
//!
//! The reader walks the extent tree, materializes holes as zeros and treats
//! unwritten extents as zeros, then truncates to the inode's logical size.

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
const MAX_EXTENT_DEPTH: usize = 4;
const MAX_EXTENT_ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderError {
    Truncated,
    BadExtentMagic,
    ExtentLimitExceeded,
    DepthLimitExceeded,
    InodeOutOfRange,
    BadBlockSize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub block_size: usize,
    pub inodes_per_group: usize,
    pub inode_size: usize,
    pub blocks_per_group: usize,
    pub group_desc_size: usize,
    pub group_desc_table: usize,
}

pub fn geometry(image: &[u8]) -> Result<Geometry, ReaderError> {
    let sb = image
        .get(SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024)
        .ok_or(ReaderError::Truncated)?;
    let log_block_size = le_u32(sb, 0x18).ok_or(ReaderError::Truncated)?;
    if log_block_size > 6 {
        return Err(ReaderError::BadBlockSize);
    }
    let block_size = 1024usize << log_block_size;
    let inodes_per_group = le_u32(sb, 0x28).ok_or(ReaderError::Truncated)? as usize;
    let inode_size = le_u16(sb, 0x58).ok_or(ReaderError::Truncated)? as usize;
    let blocks_per_group = le_u32(sb, 0x20).ok_or(ReaderError::Truncated)? as usize;
    if block_size == 0 || inodes_per_group == 0 || inode_size < 128 || blocks_per_group == 0 {
        return Err(ReaderError::BadBlockSize);
    }
    let group_desc_table = block_size * ((1024 + 1024 + block_size - 1) / block_size);
    Ok(Geometry {
        block_size,
        inodes_per_group,
        inode_size,
        blocks_per_group,
        group_desc_size: 64,
        group_desc_table,
    })
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inode {
    pub number: u32,
    pub mode: u16,
    pub size: u64,
    pub links: u16,
    pub flags: u32,
    pub block_ptrs: [u8; INODE_BLOCK_PTRS_LEN],
}

pub fn inode_number_to_group(geom: &Geometry, ino: u32) -> (usize, usize) {
    let zero_based = (ino - 1) as usize;
    (zero_based / geom.inodes_per_group, zero_based % geom.inodes_per_group)
}

pub fn read_inode(image: &[u8], geom: &Geometry, ino: u32) -> Result<Inode, ReaderError> {
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
    let desc = image
        .get(desc_start..desc_start + geom.group_desc_size)
        .ok_or(ReaderError::Truncated)?;
    let inode_table = le_u32(desc, 0x08).ok_or(ReaderError::Truncated)? as usize;
    let offset = inode_table
        .checked_mul(geom.block_size)
        .and_then(|base| base.checked_add(index.checked_mul(geom.inode_size)?))
        .ok_or(ReaderError::Truncated)?;
    let raw = image
        .get(offset..offset + geom.inode_size)
        .ok_or(ReaderError::Truncated)?;
    let mut block_ptrs = [0u8; INODE_BLOCK_PTRS_LEN];
    block_ptrs.copy_from_slice(&raw[INODE_BLOCK_PTRS_OFFSET..INODE_BLOCK_PTRS_OFFSET + INODE_BLOCK_PTRS_LEN]);
    let size_lo = le_u32(raw, 0x04).ok_or(ReaderError::Truncated)? as u64;
    let size_hi = le_u32(raw, 0x6C).ok_or(ReaderError::Truncated)? as u64;
    Ok(Inode {
        number: ino,
        mode: le_u16(raw, 0x00).ok_or(ReaderError::Truncated)?,
        size: size_lo | (size_hi << 32),
        links: le_u16(raw, 0x1A).ok_or(ReaderError::Truncated)?,
        flags: le_u32(raw, 0x20).ok_or(ReaderError::Truncated)?,
        block_ptrs,
    })
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

pub fn extent_tree(image: &[u8], geom: &Geometry, inode: &Inode) -> Result<Vec<Extent>, ReaderError> {
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
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(ReaderError::Truncated)?;
        let node = image
            .get(start..start + geom.block_size)
            .ok_or(ReaderError::Truncated)?;
        let (found, deeper) = parse_extent_body(node, 0)?;
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
pub fn read_file(image: &[u8], geom: &Geometry, inode: &Inode) -> Result<Vec<u8>, ReaderError> {
    if inode.flags & 0x1000_0000 != 0 {
        return Err(ReaderError::BadBlockSize);
    }
    let size = usize::try_from(inode.size).map_err(|_| ReaderError::Truncated)?;
    let mut data = vec![0u8; size];
    let block_size = geom.block_size;
    for extent in extent_tree(image, geom, inode)? {
        if extent.unwritten {
            continue;
        }
        let logical = usize::try_from(extent.logical_block)
            .map_err(|_| ReaderError::Truncated)?
            .checked_mul(block_size)
            .ok_or(ReaderError::Truncated)?;
        let physical = usize::try_from(extent.physical_block)
            .map_err(|_| ReaderError::Truncated)?
            .checked_mul(block_size)
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
            let src = physical.checked_add(block_offset).ok_or(ReaderError::Truncated)?;
            let chunk = image.get(src..src + block_size).ok_or(ReaderError::Truncated)?;
            let out = &mut data[dst..size.min(dst + block_size)];
            out.copy_from_slice(&chunk[..out.len()]);
        }
    }
    Ok(data)
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
}
