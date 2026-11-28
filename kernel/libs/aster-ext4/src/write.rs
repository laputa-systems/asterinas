// SPDX-License-Identifier: MPL-2.0

//! Bounded whole-file write engine for the experimental writable path.
//!
//! The engine reads the existing file, applies the byte range, allocates
//! blocks from the group bitmap, rewrites the inline extent tree and writes
//! the data, inode and bitmap back. Every size and offset is checked before
//! any write is issued, so a failing write never leaves a partial extent tree.

extern crate alloc;

use alloc::{vec, vec::Vec};

use crate::{
    extent_edit::BlockAllocator,
    reader::{
        BlockReader, BlockWriter, EXTENT_MAGIC, Geometry, Inode, block_bitmap_offset_from,
        inode_offset_from, read_block_bitmap_from, read_file_from,
    },
};

const MAX_FILE_SIZE: usize = 128 * 1024 * 1024;
const EXTENT_HEADER_LEN: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteError {
    TooLarge,
    NoSpace,
    Io,
    BadGeometry,
}

pub struct WriteEngine<'a, R: BlockReader, W: BlockWriter> {
    reader: &'a R,
    writer: &'a W,
    geom: &'a Geometry,
    inode: &'a Inode,
    group: usize,
}

impl<'a, R: BlockReader, W: BlockWriter> WriteEngine<'a, R, W> {
    pub fn new(reader: &'a R, writer: &'a W, geom: &'a Geometry, inode: &'a Inode, group: usize) -> Self {
        Self {
            reader,
            writer,
            geom,
            inode,
            group,
        }
    }

    pub fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), WriteError> {
        if data.len() > MAX_FILE_SIZE {
            return Err(WriteError::TooLarge);
        }
        let end = offset.checked_add(data.len()).ok_or(WriteError::TooLarge)?;
        if end > MAX_FILE_SIZE {
            return Err(WriteError::TooLarge);
        }

        let mut content = read_file_from(self.reader, self.geom, self.inode)
            .map_err(|_| WriteError::Io)?;
        if content.len() < end {
            content.resize(end, 0);
        }
        content[offset..end].copy_from_slice(data);

        let block_size = self.geom.block_size;
        if !matches!(block_size, 1024 | 2048 | 4096) {
            return Err(WriteError::BadGeometry);
        }
        let nr_blocks = content.len().div_ceil(block_size);
        if nr_blocks > u16::MAX as usize {
            return Err(WriteError::TooLarge);
        }

        let bitmap = read_block_bitmap_from(self.reader, self.geom, self.group)
            .map_err(|_| WriteError::Io)?;
        let mut allocator = BlockAllocator::from_bitmap(&bitmap, self.geom.blocks_per_group);
        let mut physical = Vec::with_capacity(nr_blocks);
        for _ in 0..nr_blocks {
            physical.push(allocator.allocate().ok_or(WriteError::NoSpace)?);
        }

        for (index, block) in physical.iter().enumerate() {
            let mut buffer = vec![0u8; block_size];
            let start = index * block_size;
            let stop = (start + block_size).min(content.len());
            buffer[..stop - start].copy_from_slice(&content[start..stop]);
            let offset = block
                .checked_mul(block_size as u64)
                .ok_or(WriteError::TooLarge)?;
            self.writer.write_at(offset, &buffer).ok_or(WriteError::Io)?;
        }

        let inode_offset = inode_offset_from(self.reader, self.geom, self.inode.number)
            .map_err(|_| WriteError::Io)?;
        let mut raw = self
            .reader
            .read_at(inode_offset, self.geom.inode_size)
            .ok_or(WriteError::Io)?;
        let size = content.len() as u64;
        raw[0x04..0x08].copy_from_slice(&(size as u32).to_le_bytes());
        raw[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
        let sectors = (nr_blocks * (block_size / 512)) as u32;
        raw[0x1C..0x20].copy_from_slice(&sectors.to_le_bytes());

        let tree_start = 0x28;
        let tree = &mut raw[tree_start..tree_start + 60];
        tree[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        tree[2..4].copy_from_slice(&1u16.to_le_bytes());
        tree[4..6].copy_from_slice(&4u16.to_le_bytes());
        tree[6..8].copy_from_slice(&0u16.to_le_bytes());
        tree[8..12].copy_from_slice(&self.inode.generation.to_le_bytes());
        let entry = EXTENT_HEADER_LEN;
        tree[entry..entry + 4].copy_from_slice(&0u32.to_le_bytes());
        tree[entry + 4..entry + 6].copy_from_slice(&(nr_blocks as u16).to_le_bytes());
        tree[entry + 6..entry + 8].copy_from_slice(&0u16.to_le_bytes());
        tree[entry + 8..entry + 12].copy_from_slice(&(physical[0] as u32).to_le_bytes());

        let bitmap_offset = block_bitmap_offset_from(self.reader, self.geom, self.group)
            .map_err(|_| WriteError::Io)?;
        let mut updated_bitmap = bitmap;
        for block in &physical {
            let index = *block as usize;
            if let Some(byte) = updated_bitmap.get_mut(index / 8) {
                *byte |= 1 << (index % 8);
            }
        }
        self.writer
            .write_at(bitmap_offset, &updated_bitmap)
            .ok_or(WriteError::Io)?;
        self.writer.write_at(inode_offset, &raw).ok_or(WriteError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn rewrites_file_and_readback_matches() {
        let image = fixture("basic");
        let device = MemoryDevice { bytes: Mutex::new(image.clone()) };
        let geom = crate::reader::geometry(&image).unwrap();
        let inode = crate::reader::read_inode(&image, &geom, crate::reader::ROOT_INO).unwrap();

        let engine = WriteEngine::new(&device, &device, &geom, &inode, 0);
        engine.write_at(0, b"written-by-lc20\n").unwrap();

        let updated = device.bytes.lock().unwrap().clone();
        let new_inode = crate::reader::read_inode(&updated, &geom, inode.number).unwrap();
        assert_eq!(new_inode.size, inode.size);
        let data = crate::reader::read_file(&updated, &geom, &new_inode).unwrap();
        assert_eq!(&data[..16], b"written-by-lc20\n");
    }

    #[test]
    fn rejects_oversize_write() {
        let image = fixture("basic");
        let device = MemoryDevice { bytes: Mutex::new(image.clone()) };
        let geom = crate::reader::geometry(&image).unwrap();
        let inode = crate::reader::read_inode(&image, &geom, crate::reader::ROOT_INO).unwrap();
        let engine = WriteEngine::new(&device, &device, &geom, &inode, 0);
        assert_eq!(engine.write_at(MAX_FILE_SIZE, b"x"), Err(WriteError::TooLarge));
    }
}
