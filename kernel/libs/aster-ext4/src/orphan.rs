// SPDX-License-Identifier: MPL-2.0

//! Bounded ext4 orphan-list management and recovery-side cleanup.
//!
//! `s_last_orphan` heads a singly linked list whose nodes are linked through
//! the inode's `i_dtime` field. A crash between linking an inode and removing
//! it leaves the node on disk; mount-time cleanup truncates those inodes and
//! clears the list so deallocation can be retried.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    SUPER_BLOCK_OFFSET,
    reader::{BlockReader, BlockWriter, Geometry, inode_offset_from},
};

pub const ORPHAN_HEAD_OFFSET: usize = 0x164;
pub const ORPHAN_NEXT_OFFSET: usize = 0x14;
const MAX_ORPHANS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrphanError {
    Truncated,
    Io,
    Cycle,
    Full,
}

fn read_head(reader: &dyn BlockReader) -> Result<u32, OrphanError> {
    let sb = reader
        .read_at(SUPER_BLOCK_OFFSET as u64, 1024)
        .ok_or(OrphanError::Truncated)?;
    let bytes = sb
        .get(ORPHAN_HEAD_OFFSET..ORPHAN_HEAD_OFFSET + 4)
        .ok_or(OrphanError::Truncated)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn write_head(writer: &dyn BlockWriter, ino: u32) -> Result<(), OrphanError> {
    writer
        .write_at(SUPER_BLOCK_OFFSET as u64 + ORPHAN_HEAD_OFFSET as u64, &ino.to_le_bytes())
        .ok_or(OrphanError::Io)
}

fn read_next(reader: &dyn BlockReader, geom: &Geometry, ino: u32) -> Result<u32, OrphanError> {
    let offset = inode_offset_from(reader, geom, ino).map_err(|_| OrphanError::Truncated)?;
    let raw = reader
        .read_at(offset, geom.inode_size)
        .ok_or(OrphanError::Truncated)?;
    let bytes = raw
        .get(ORPHAN_NEXT_OFFSET..ORPHAN_NEXT_OFFSET + 4)
        .ok_or(OrphanError::Truncated)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn write_next(
    reader: &dyn BlockReader,
    writer: &dyn BlockWriter,
    geom: &Geometry,
    ino: u32,
    next: u32,
) -> Result<(), OrphanError> {
    let offset = inode_offset_from(reader, geom, ino).map_err(|_| OrphanError::Truncated)?;
    let mut raw = reader
        .read_at(offset, geom.inode_size)
        .ok_or(OrphanError::Truncated)?;
    let slot = raw
        .get_mut(ORPHAN_NEXT_OFFSET..ORPHAN_NEXT_OFFSET + 4)
        .ok_or(OrphanError::Truncated)?;
    slot.copy_from_slice(&next.to_le_bytes());
    writer.write_at(offset, &raw).ok_or(OrphanError::Io)
}

/// Links `ino` at the head of the orphan list.
pub fn add<R: BlockReader, W: BlockWriter>(
    reader: &R,
    writer: &W,
    geom: &Geometry,
    ino: u32,
) -> Result<(), OrphanError> {
    let head = read_head(reader)?;
    if head == ino {
        return Ok(());
    }
    write_next(reader, writer, geom, ino, head)?;
    write_head(writer, ino)
}

/// Removes `ino` from the orphan list, if present.
pub fn remove<R: BlockReader, W: BlockWriter>(
    reader: &R,
    writer: &W,
    geom: &Geometry,
    ino: u32,
) -> Result<bool, OrphanError> {
    let mut current = read_head(reader)?;
    let mut previous = 0u32;
    for _ in 0..MAX_ORPHANS {
        if current == 0 {
            return Ok(false);
        }
        let next = read_next(reader, geom, current)?;
        if current == ino {
            if previous == 0 {
                write_head(writer, next)?;
            } else {
                write_next(reader, writer, geom, previous, next)?;
            }
            write_next(reader, writer, geom, current, 0)?;
            return Ok(true);
        }
        previous = current;
        current = next;
    }
    Err(OrphanError::Cycle)
}

/// Returns the orphan list in on-disk order.
pub fn collect(reader: &dyn BlockReader, geom: &Geometry) -> Result<Vec<u32>, OrphanError> {
    let mut entries = Vec::new();
    let mut current = read_head(reader)?;
    while current != 0 {
        if entries.len() >= MAX_ORPHANS {
            return Err(OrphanError::Full);
        }
        entries.push(current);
        current = read_next(reader, geom, current)?;
    }
    Ok(entries)
}

/// Truncates every orphaned inode and clears the list. Returns the number of
/// inodes processed.
pub fn cleanup<R: BlockReader, W: BlockWriter>(
    reader: &R,
    writer: &W,
    geom: &Geometry,
) -> Result<usize, OrphanError> {
    let entries = collect(reader, geom)?;
    if entries.is_empty() {
        return Ok(0);
    }
    for ino in &entries {
        let offset = inode_offset_from(reader, geom, *ino).map_err(|_| OrphanError::Truncated)?;
        let mut raw = reader
            .read_at(offset, geom.inode_size)
            .ok_or(OrphanError::Truncated)?;
        raw[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
        raw[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
        raw[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
        raw[0x1A..0x1C].copy_from_slice(&0u16.to_le_bytes());
        raw[0x28..0x64].fill(0);
        raw[ORPHAN_NEXT_OFFSET..ORPHAN_NEXT_OFFSET + 4].fill(0);
        writer.write_at(offset, &raw).ok_or(OrphanError::Io)?;
    }
    write_head(writer, 0)?;
    Ok(entries.len())
}

/// In-memory counterpart of [`cleanup`], used by mount-time recovery where a
/// single mutable image is both the reader and the writer.
pub fn cleanup_image(image: &mut [u8]) -> Result<usize, OrphanError> {
    let geom = crate::reader::geometry(image).map_err(|_| OrphanError::Truncated)?;
    let entries = {
        let reader = crate::reader::SliceReader::new(image);
        collect(&reader, &geom)?
    };
    if entries.is_empty() {
        return Ok(0);
    }
    for ino in &entries {
        let offset = {
            let reader = crate::reader::SliceReader::new(image);
            let offset = inode_offset_from(&reader, &geom, *ino)
                .map_err(|_| OrphanError::Truncated)?;
            usize::try_from(offset).map_err(|_| OrphanError::Truncated)?
        };
        let raw = image
            .get_mut(offset..offset.checked_add(geom.inode_size).ok_or(OrphanError::Truncated)?)
            .ok_or(OrphanError::Truncated)?;
        raw[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());
        raw[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
        raw[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes());
        raw[0x1A..0x1C].copy_from_slice(&0u16.to_le_bytes());
        raw[0x28..0x64].fill(0);
        raw[ORPHAN_NEXT_OFFSET..ORPHAN_NEXT_OFFSET + 4].fill(0);
    }
    let sb = image
        .get_mut(SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024)
        .ok_or(OrphanError::Truncated)?;
    sb[ORPHAN_HEAD_OFFSET..ORPHAN_HEAD_OFFSET + 4].fill(0);
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::geometry;
    use std::{fs, path::PathBuf, sync::Mutex};

    struct MemoryDevice {
        bytes: Mutex<Vec<u8>>,
    }

    impl BlockReader for MemoryDevice {
        fn read_at(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
            let start = usize::try_from(offset).ok()?;
            self.bytes.lock().unwrap().get(start..start.checked_add(len)?).map(|s| s.to_vec())
        }
    }

    impl BlockWriter for MemoryDevice {
        fn write_at(&self, offset: u64, data: &[u8]) -> Option<()> {
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(data.len())?;
            let mut bytes = self.bytes.lock().unwrap();
            let slot = bytes.get_mut(start..end)?;
            slot.copy_from_slice(data);
            Some(())
        }
    }

    fn fixture() -> Vec<u8> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.pop();
        path.push("target/qualification/inputs/ext4/basic.ext4");
        fs::read(path).unwrap()
    }

    #[test]
    fn orphan_chain_round_trip_and_cleanup() {
        let image = fixture();
        let geom = geometry(&image).unwrap();
        let device = MemoryDevice { bytes: Mutex::new(image) };

        assert_eq!(collect(&device, &geom), Ok(Vec::new()));
        add(&device, &device, &geom, 11).unwrap();
        add(&device, &device, &geom, 12).unwrap();
        assert_eq!(collect(&device, &geom), Ok(vec![12, 11]));

        assert_eq!(remove(&device, &device, &geom, 11), Ok(true));
        assert_eq!(collect(&device, &geom), Ok(vec![12]));
        assert_eq!(remove(&device, &device, &geom, 12), Ok(true));
        assert_eq!(collect(&device, &geom), Ok(Vec::new()));
        assert_eq!(remove(&device, &device, &geom, 12), Ok(false));

        add(&device, &device, &geom, 11).unwrap();
        assert_eq!(cleanup(&device, &device, &geom), Ok(1));
        assert_eq!(collect(&device, &geom), Ok(Vec::new()));
    }

    #[test]
    fn cleanup_truncates_orphan_inode() {
        let image = fixture();
        let geom = geometry(&image).unwrap();
        let device = MemoryDevice { bytes: Mutex::new(image) };
        add(&device, &device, &geom, 11).unwrap();
        cleanup(&device, &device, &geom).unwrap();
        let offset = inode_offset_from(&device, &geom, 11).unwrap();
        let raw = device.read_at(offset, geom.inode_size).unwrap();
        assert_eq!(&raw[0x04..0x08], &0u32.to_le_bytes());
        assert_eq!(&raw[0x28..0x64], &vec![0u8; 60][..]);
    }
}
