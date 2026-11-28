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
    jbd2::JOURNAL_BLOCK_SIZE,
    reader::{
        BlockReader, BlockWriter, EXTENT_MAGIC, Geometry, Inode, block_bitmap_offset_from,
        inode_offset_from, read_block_bitmap_from, read_file_from,
    },
    transaction::Transaction,
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

    fn prepare(&self, offset: usize, data: &[u8]) -> Result<Prepared, WriteError> {
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
        let mut allocator = BlockAllocator::from_bitmap(&bitmap, self.geom.usable_blocks(self.group));
        let mut physical = Vec::with_capacity(nr_blocks);
        for _ in 0..nr_blocks {
            physical.push(allocator.allocate().ok_or(WriteError::NoSpace)?);
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

        let tree = &mut raw[0x28..0x28 + 60];
        tree[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        tree[2..4].copy_from_slice(&1u16.to_le_bytes());
        tree[4..6].copy_from_slice(&4u16.to_le_bytes());
        tree[6..8].copy_from_slice(&0u16.to_le_bytes());
        tree[8..12].copy_from_slice(&self.inode.generation.to_le_bytes());
        tree[EXTENT_HEADER_LEN..EXTENT_HEADER_LEN + 4].copy_from_slice(&0u32.to_le_bytes());
        tree[EXTENT_HEADER_LEN + 4..EXTENT_HEADER_LEN + 6]
            .copy_from_slice(&(nr_blocks as u16).to_le_bytes());
        tree[EXTENT_HEADER_LEN + 6..EXTENT_HEADER_LEN + 8].copy_from_slice(&0u16.to_le_bytes());
        tree[EXTENT_HEADER_LEN + 8..EXTENT_HEADER_LEN + 12]
            .copy_from_slice(&(physical[0] as u32).to_le_bytes());

        let bitmap_offset = block_bitmap_offset_from(self.reader, self.geom, self.group)
            .map_err(|_| WriteError::Io)?;
        let mut updated_bitmap = bitmap;
        for block in &physical {
            let index = *block as usize;
            if let Some(byte) = updated_bitmap.get_mut(index / 8) {
                *byte |= 1 << (index % 8);
            }
        }

        Ok(Prepared {
            content,
            physical,
            inode_offset,
            raw,
            bitmap_offset,
            updated_bitmap,
        })
    }

    fn apply(&self, prepared: &Prepared) -> Result<(), WriteError> {
        let block_size = self.geom.block_size;
        for (index, block) in prepared.physical.iter().enumerate() {
            let mut buffer = vec![0u8; block_size];
            let start = index * block_size;
            let stop = (start + block_size).min(prepared.content.len());
            buffer[..stop - start].copy_from_slice(&prepared.content[start..stop]);
            let offset = block
                .checked_mul(block_size as u64)
                .ok_or(WriteError::TooLarge)?;
            self.writer.write_at(offset, &buffer).ok_or(WriteError::Io)?;
        }
        self.writer
            .write_at(prepared.bitmap_offset, &prepared.updated_bitmap)
            .ok_or(WriteError::Io)?;
        self.writer
            .write_at(prepared.inode_offset, &prepared.raw)
            .ok_or(WriteError::Io)?;
        Ok(())
    }

    pub fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), WriteError> {
        let prepared = self.prepare(offset, data)?;
        self.apply(&prepared)
    }

    /// Writes the data through a JBD2 transaction whose descriptor/data/commit
    /// records are emitted into `journal`. The journal record is parseable by
    /// `jbd2::recovery_plan`, giving the write path one on-disk contract with
    /// recovery.
    fn journal_prepared(&self, prepared: &Prepared, journal: &mut [u8]) -> Result<(), WriteError> {
        let total = journal.len() / JOURNAL_BLOCK_SIZE;
        let mut tx = Transaction::begin(self.inode.generation, total);
        tx.reserve_credits(prepared.physical.len() as u32 + 2)
            .map_err(|_| WriteError::NoSpace)?;
        let block_size = self.geom.block_size;
        for (index, block) in prepared.physical.iter().enumerate() {
            let mut buffer = vec![0u8; block_size];
            let begin = index * block_size;
            let stop = (begin + block_size).min(prepared.content.len());
            buffer[..stop - begin].copy_from_slice(&prepared.content[begin..stop]);
            tx.add_ordered_data(*block, buffer)
                .map_err(|_| WriteError::NoSpace)?;
        }
        tx.commit(journal).map_err(|_| WriteError::NoSpace)?;
        Ok(())
    }

    pub fn write_at_journaled(
        &self,
        offset: usize,
        data: &[u8],
        journal: &mut [u8],
    ) -> Result<(), WriteError> {
        let prepared = self.prepare(offset, data)?;
        self.journal_prepared(&prepared, journal)?;
        self.apply(&prepared)
    }

    /// Emits the journal record and writes it to a journal region before
    /// applying the data and metadata updates.
    pub fn write_at_journaled_to(
        &self,
        offset: usize,
        data: &[u8],
        journal: &mut [u8],
        journal_writer: &dyn BlockWriter,
        journal_start: u64,
    ) -> Result<(), WriteError> {
        let prepared = self.prepare(offset, data)?;
        self.journal_prepared(&prepared, journal)?;
        journal_writer
            .write_at(journal_start, journal)
            .ok_or(WriteError::Io)?;
        self.apply(&prepared)
    }
}

struct Prepared {
    content: Vec<u8>,
    physical: Vec<u64>,
    inode_offset: u64,
    raw: Vec<u8>,
    bitmap_offset: u64,
    updated_bitmap: Vec<u8>,
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
    fn journaled_write_round_trips_through_recovery() {
        let image = fixture("basic");
        let device = MemoryDevice { bytes: Mutex::new(image.clone()) };
        let geom = crate::reader::geometry(&image).unwrap();
        let inode = crate::reader::read_inode(&image, &geom, crate::reader::ROOT_INO).unwrap();
        let mut journal = vec![0u8; 8 * JOURNAL_BLOCK_SIZE];

        let engine = WriteEngine::new(&device, &device, &geom, &inode, 0);
        engine
            .write_at_journaled(0, b"journaled-write\n", &mut journal)
            .unwrap();

        let sb = crate::jbd2::parse_superblock(&journal).unwrap();
        let plan = crate::jbd2::recovery_plan(&journal, &sb).unwrap();
        assert_eq!(plan.actions.len(), 1);
        let updated = device.bytes.lock().unwrap().clone();
        let new_inode = crate::reader::read_inode(&updated, &geom, inode.number).unwrap();
        let data = crate::reader::read_file(&updated, &geom, &new_inode).unwrap();
        assert_eq!(&data[..16], b"journaled-write\n");
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
