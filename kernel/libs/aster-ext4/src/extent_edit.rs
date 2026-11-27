// SPDX-License-Identifier: MPL-2.0

//! Bounded extent-tree editing and block allocation for LC-20.
//!
//! The editor keeps a sorted, non-overlapping extent set and implements the
//! operations a writable ext4 path needs: lookup, insert with overlap
//! splitting, contiguous merge, grow, collapse and unwritten conversion.
//! Block allocation is a bounded bitmap scan; every operation rejects ranges
//! that overflow or exceed the declared device size.

extern crate alloc;

use alloc::{vec, vec::Vec};

use crate::reader::Extent;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtentError {
    Overlap,
    NotFound,
    OutOfRange,
    NoSpace,
    Overflow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtentEditor {
    extents: Vec<Extent>,
    nr_blocks: u64,
}

impl ExtentEditor {
    pub fn new(nr_blocks: u64) -> Self {
        Self {
            extents: Vec::new(),
            nr_blocks,
        }
    }

    pub fn from_extents(extents: Vec<Extent>, nr_blocks: u64) -> Result<Self, ExtentError> {
        let mut editor = Self {
            extents: Vec::new(),
            nr_blocks,
        };
        for extent in extents {
            editor.insert(extent.logical_block, extent.physical_block, extent.len, extent.unwritten)?;
        }
        Ok(editor)
    }

    pub fn extents(&self) -> &[Extent] {
        &self.extents
    }

    fn check_range(&self, logical: u64, len: u16) -> Result<(), ExtentError> {
        if len == 0 {
            return Err(ExtentError::OutOfRange);
        }
        let end = logical.checked_add(u64::from(len)).ok_or(ExtentError::Overflow)?;
        if end > self.nr_blocks {
            return Err(ExtentError::OutOfRange);
        }
        Ok(())
    }

    /// Inserts a mapping, splitting any extents it overlaps.
    pub fn insert(
        &mut self,
        logical: u64,
        physical: u64,
        len: u16,
        unwritten: bool,
    ) -> Result<(), ExtentError> {
        self.check_range(logical, len)?;
        let physical_end = physical
            .checked_add(u64::from(len))
            .ok_or(ExtentError::Overflow)?;
        if physical_end > self.nr_blocks {
            return Err(ExtentError::OutOfRange);
        }
        let end = logical + u64::from(len);

        let mut result = Vec::with_capacity(self.extents.len() + 2);
        for extent in &self.extents {
            let extent_end = extent
                .logical_block
                .checked_add(u64::from(extent.len))
                .ok_or(ExtentError::Overflow)?;
            if extent_end <= logical || extent.logical_block >= end {
                result.push(*extent);
                continue;
            }
            if extent.logical_block < logical {
                let keep = logical - extent.logical_block;
                let keep = u16::try_from(keep).map_err(|_| ExtentError::OutOfRange)?;
                result.push(Extent {
                    logical_block: extent.logical_block,
                    physical_block: extent.physical_block,
                    len: keep,
                    unwritten: extent.unwritten,
                });
            }
            if extent_end > end {
                let skip = end - extent.logical_block;
                let skip = u16::try_from(skip).map_err(|_| ExtentError::OutOfRange)?;
                let remaining = extent.len.checked_sub(skip).ok_or(ExtentError::Overflow)?;
                result.push(Extent {
                    logical_block: end,
                    physical_block: extent.physical_block.checked_add(u64::from(skip)).ok_or(ExtentError::Overflow)?,
                    len: remaining,
                    unwritten: extent.unwritten,
                });
            }
        }
        result.push(Extent {
            logical_block: logical,
            physical_block: physical,
            len,
            unwritten,
        });
        result.sort_by_key(|item| item.logical_block);
        self.extents = result;
        Ok(())
    }

    pub fn lookup(&self, logical: u64) -> Option<&Extent> {
        self.extents.iter().find(|extent| {
            let end = extent.logical_block + u64::from(extent.len);
            logical >= extent.logical_block && logical < end
        })
    }

    /// Splits the extent covering `logical` at that logical block.
    pub fn split(&mut self, logical: u64) -> Result<(), ExtentError> {
        let index = self
            .extents
            .iter()
            .position(|extent| {
                let end = extent.logical_block + u64::from(extent.len);
                logical > extent.logical_block && logical < end
            })
            .ok_or(ExtentError::NotFound)?;
        let extent = self.extents[index];
        let left = u16::try_from(logical - extent.logical_block)
            .map_err(|_| ExtentError::OutOfRange)?;
        let right = extent.len.checked_sub(left).ok_or(ExtentError::Overflow)?;
        self.extents.remove(index);
        self.extents.insert(index, Extent {
            logical_block: logical,
            physical_block: extent.physical_block.checked_add(u64::from(left)).ok_or(ExtentError::Overflow)?,
            len: right,
            unwritten: extent.unwritten,
        });
        self.extents.insert(index, Extent {
            logical_block: extent.logical_block,
            physical_block: extent.physical_block,
            len: left,
            unwritten: extent.unwritten,
        });
        Ok(())
    }

    /// Merges contiguous extents whose physical blocks are also contiguous
    /// and whose unwritten state agrees. Returns the number of merges.
    pub fn merge(&mut self) -> usize {
        let mut merged = 0usize;
        let mut index = 0usize;
        while index + 1 < self.extents.len() {
            let left = self.extents[index];
            let right = self.extents[index + 1];
            let left_end = left.logical_block + u64::from(left.len);
            let physical_end = left.physical_block + u64::from(left.len);
            let combined = left.len.checked_add(right.len);
            if left_end == right.logical_block
                && physical_end == right.physical_block
                && left.unwritten == right.unwritten
                && combined.is_some_and(|len| len <= u16::MAX)
            {
                self.extents[index].len = combined.unwrap();
                self.extents.remove(index + 1);
                merged += 1;
            } else {
                index += 1;
            }
        }
        merged
    }

    pub fn grow(&mut self, logical: u64, extra: u16) -> Result<(), ExtentError> {
        let index = self
            .extents
            .iter()
            .position(|extent| extent.logical_block == logical)
            .ok_or(ExtentError::NotFound)?;
        let extent = self.extents[index];
        let len = extent.len.checked_add(extra).ok_or(ExtentError::Overflow)?;
        self.check_range(logical, len)?;
        self.extents[index].len = len;
        Ok(())
    }

    /// Removes a logical range, splitting extents at both ends.
    pub fn collapse(&mut self, logical: u64, len: u16) -> Result<(), ExtentError> {
        self.check_range(logical, len)?;
        self.split(logical).ok();
        let end = logical + u64::from(len);
        self.split(end).ok();
        self.extents.retain(|extent| {
            let extent_end = extent.logical_block + u64::from(extent.len);
            extent_end <= logical || extent.logical_block >= end
        });
        Ok(())
    }

    pub fn mark_written(&mut self, logical: u64, len: u16) -> Result<(), ExtentError> {
        self.split(logical).ok();
        let end = logical + u64::from(len);
        self.split(end).ok();
        let mut found = false;
        for extent in &mut self.extents {
            let extent_end = extent.logical_block + u64::from(extent.len);
            if extent.logical_block >= logical && extent_end <= end {
                extent.unwritten = false;
                found = true;
            }
        }
        if found { Ok(()) } else { Err(ExtentError::NotFound) }
    }
}

/// A bounded physical block allocator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockAllocator {
    used: Vec<bool>,
    next: usize,
}

impl BlockAllocator {
    pub fn new(nr_blocks: usize) -> Self {
        Self {
            used: vec![false; nr_blocks],
            next: 0,
        }
    }

    pub fn allocate(&mut self) -> Option<u64> {
        let len = self.used.len();
        for offset in 0..len {
            let index = (self.next + offset) % len;
            if !self.used[index] {
                self.used[index] = true;
                self.next = (index + 1) % len;
                return Some(index as u64);
            }
        }
        None
    }

    pub fn free(&mut self, block: u64) -> Result<(), ExtentError> {
        let index = usize::try_from(block).map_err(|_| ExtentError::OutOfRange)?;
        let slot = self.used.get_mut(index).ok_or(ExtentError::OutOfRange)?;
        if !*slot {
            return Err(ExtentError::NoSpace);
        }
        *slot = false;
        Ok(())
    }

    pub fn used_count(&self) -> usize {
        self.used.iter().filter(|used| **used).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extent(logical: u64, physical: u64, len: u16) -> Extent {
        Extent {
            logical_block: logical,
            physical_block: physical,
            len,
            unwritten: false,
        }
    }

    #[test]
    fn insert_splits_overlap_and_keeps_order() {
        let mut editor = ExtentEditor::new(1024);
        editor.insert(0, 100, 8, false).unwrap();
        editor.insert(10, 200, 8, false).unwrap();
        editor.insert(3, 300, 4, true).unwrap();
        let extents = editor.extents();
        assert_eq!(extents.len(), 4);
        assert_eq!(extents[0].len, 3);
        assert_eq!(extents[1].logical_block, 3);
        assert!(extents[1].unwritten);
        assert_eq!(extents[2].logical_block, 7);
        assert_eq!(extents[2].len, 1);
        assert_eq!(extents[3].logical_block, 10);
    }

    #[test]
    fn merge_contiguous_extents() {
        let mut editor = ExtentEditor::new(1024);
        editor.insert(0, 100, 4, false).unwrap();
        editor.insert(4, 104, 4, false).unwrap();
        editor.insert(8, 200, 4, false).unwrap();
        assert_eq!(editor.merge(), 1);
        assert_eq!(editor.extents().len(), 2);
        assert_eq!(editor.extents()[0].len, 8);
    }

    #[test]
    fn grow_collapse_and_convert() {
        let mut editor = ExtentEditor::new(1024);
        editor.insert(0, 100, 4, true).unwrap();
        editor.grow(0, 4).unwrap();
        assert_eq!(editor.lookup(5).unwrap().len, 8);
        editor.mark_written(2, 2).unwrap();
        assert!(!editor.lookup(2).unwrap().unwritten);
        assert!(editor.lookup(6).unwrap().unwritten);
        editor.collapse(1, 2).unwrap();
        assert!(editor.lookup(1).is_none());
        assert!(editor.lookup(5).is_some());
    }

    #[test]
    fn allocator_reuses_freed_blocks_and_rejects_double_free() {
        let mut allocator = BlockAllocator::new(2);
        assert_eq!(allocator.allocate(), Some(0));
        assert_eq!(allocator.allocate(), Some(1));
        assert_eq!(allocator.allocate(), None);
        allocator.free(0).unwrap();
        assert_eq!(allocator.allocate(), Some(0));
        assert_eq!(allocator.free(5), Err(ExtentError::OutOfRange));
    }

    #[test]
    fn rejects_out_of_range_and_overflow() {
        let mut editor = ExtentEditor::new(10);
        assert_eq!(
            editor.insert(8, 0, 4, false),
            Err(ExtentError::OutOfRange)
        );
        assert_eq!(
            editor.insert(u64::MAX, 0, 2, false),
            Err(ExtentError::Overflow)
        );
        let extents = vec![extent(0, 0, 4), extent(4, 4, 4)];
        let rebuilt = ExtentEditor::from_extents(extents, 10).unwrap();
        assert_eq!(rebuilt.extents().len(), 2);
    }
}
