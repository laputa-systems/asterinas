// SPDX-License-Identifier: MPL-2.0

//! Implements `aster_ext4`'s `BlockReader` over a kernel block device.

use aster_block::{
    BLOCK_SIZE, BlockDevice,
    bio::{BioDirection, BioSegment, BioStatus},
    id::Bid,
};
use aster_ext4::reader::{BlockReader, BlockWriter};
use ostd::mm::io::util::HasVmReaderWriter;

use crate::prelude::*;

pub(super) struct DeviceReader {
    device: Arc<dyn BlockDevice>,
}

impl DeviceReader {
    pub(super) fn new(device: Arc<dyn BlockDevice>) -> Self {
        Self { device }
    }
}

impl BlockReader for DeviceReader {
    fn read_at(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(offset).ok()?;
        let end = offset.checked_add(len)?;
        if len == 0 {
            return Some(Vec::new());
        }
        let first = offset / BLOCK_SIZE;
        let last = end.div_ceil(BLOCK_SIZE);
        let nblocks = last.checked_sub(first)?;
        if nblocks == 0 {
            return None;
        }

        let segment = BioSegment::alloc(nblocks, BioDirection::FromDevice);
        let status = self
            .device
            .read_blocks(Bid::new(first as u64), vec![segment.clone()])
            .ok()?;
        if status != BioStatus::Complete {
            return None;
        }

        let mut buffer = vec![0u8; nblocks * BLOCK_SIZE];
        let mut reader = segment.reader().ok()?;
        let mut writer = VmWriter::from(buffer.as_mut_slice());
        if reader.read(&mut writer) != buffer.len() {
            return None;
        }

        let inner = offset - first * BLOCK_SIZE;
        buffer.get(inner..inner.checked_add(len)?).map(|s| s.to_vec())
    }
}

impl BlockWriter for DeviceReader {
    fn write_at(&self, offset: u64, data: &[u8]) -> Option<()> {
        let offset = usize::try_from(offset).ok()?;
        let end = offset.checked_add(data.len())?;
        if data.is_empty() {
            return Some(());
        }
        let first = offset / BLOCK_SIZE;
        let last = end.div_ceil(BLOCK_SIZE);
        let nblocks = last.checked_sub(first)?;

        let segment = BioSegment::alloc(nblocks, BioDirection::ToDevice);
        {
            let mut writer = segment.writer().ok()?;
            writer.skip(offset - first * BLOCK_SIZE);
            let mut reader = VmReader::from(data).to_fallible();
            writer.write_fallible(&mut reader).ok()?;
        }
        let status = self
            .device
            .write_blocks(Bid::new(first as u64), vec![segment])
            .ok()?;
        if status != BioStatus::Complete {
            return None;
        }
        Some(())
    }
}
