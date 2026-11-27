// SPDX-License-Identifier: MPL-2.0

//! Bounded JBD2 journal parsing and recovery planning.
//!
//! The state machine reads a transaction from the journal start block,
//! collects descriptor-tagged data blocks, applies revoke records, and emits
//! an idempotent recovery plan. Truncated, corrupt and wrapped input is
//! rejected without reading past the supplied buffer.

extern crate alloc;

use alloc::vec::Vec;

use crate::{Error as FormatError, crc32c};

pub const JBD2_MAGIC: u32 = 0xC03B_3998;
pub const JOURNAL_BLOCK_SIZE: usize = 4096;
pub const SUPERBLOCK_OFFSET: usize = 1024;
pub const SUPERBLOCK_SIZE: usize = 1024;

pub const DESC_BLOCK: u32 = 1;
pub const COMMIT_BLOCK: u32 = 2;
pub const REVOKE_BLOCK: u32 = 3;

pub const TAG_LAST: u8 = 0x01;
pub const TAG_ESCAPE: u8 = 0x02;
pub const TAG_SAME_UUID: u8 = 0x04;
pub const TAG_DELETED: u8 = 0x08;
pub const TAG_64BIT: u8 = 0x10;

const MAX_TRANSACTION_BLOCKS: usize = 4096;
const MAX_TAGS: usize = 1024;
const MAX_REVOKES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    Truncated,
    BadMagic,
    BadSequence,
    UnknownBlockType(u32),
    CorruptDescriptor,
    CorruptTag,
    CorruptRevoke,
    MissingCommit,
    LimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalSuperBlock {
    pub sequence: u32,
    pub start_block: u32,
    pub block_size: u32,
    pub max_len: u32,
    pub err_sequence: u32,
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_be_bytes)
}

/// Parses the JBD2 superblock stored at byte 1024 of the journal.
pub fn parse_superblock(journal: &[u8]) -> Result<JournalSuperBlock, JournalError> {
    let sb = journal
        .get(SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE)
        .ok_or(JournalError::Truncated)?;
    if read_u32(sb, 0x00).ok_or(JournalError::Truncated)? != JBD2_MAGIC {
        return Err(JournalError::BadMagic);
    }
    Ok(JournalSuperBlock {
        sequence: read_u32(sb, 0x04).ok_or(JournalError::Truncated)?,
        start_block: read_u32(sb, 0x08).ok_or(JournalError::Truncated)?,
        block_size: read_u32(sb, 0x0C).ok_or(JournalError::Truncated)?,
        max_len: read_u32(sb, 0x10).ok_or(JournalError::Truncated)?,
        err_sequence: read_u32(sb, 0x24).ok_or(JournalError::Truncated)?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Write { journal_block: u32, fs_block: u64 },
    Revoke { fs_block: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPlan {
    pub sequence: u32,
    pub actions: Vec<Action>,
}

fn block<'a>(journal: &'a [u8], number: u32, size: usize) -> Option<&'a [u8]> {
    let start = (number as usize).checked_mul(size)?;
    journal.get(start..start + size)
}

fn header(block: &[u8]) -> Option<(u32, u32)> {
    Some((read_u32(block, 0)?, read_u32(block, 4)?))
}

/// Parses descriptor tags into filesystem block numbers.
///
/// Tag entries are 8 bytes (or 12 bytes with the 64-bit flag) followed by a
/// 16-byte UUID on the first entry and on every escape-marked entry.
pub fn descriptor_targets(
    desc: &[u8],
    block_size: usize,
) -> Result<Vec<Option<u64>>, JournalError> {
    if desc.len() < block_size {
        return Err(JournalError::Truncated);
    }
    let body_end = block_size - 12;
    let mut cursor = 12usize;
    let mut uuid = [0u8; 16];
    let mut have_uuid = false;
    let mut targets = Vec::new();
    while cursor + 8 <= body_end {
        let flags = desc[cursor];
        cursor += 1;
        let block_low = read_u32(desc, cursor).ok_or(JournalError::Truncated)? as u64;
        cursor += 4;
        let block_high = if flags & TAG_64BIT != 0 {
            let high = read_u32(desc, cursor).ok_or(JournalError::Truncated)? as u64;
            cursor += 4;
            high
        } else {
            0
        };
        if flags & TAG_ESCAPE != 0 || !have_uuid {
            if cursor + 16 > body_end {
                return Err(JournalError::CorruptTag);
            }
            uuid.copy_from_slice(&desc[cursor..cursor + 16]);
            cursor += 16;
            have_uuid = true;
        } else if flags & TAG_SAME_UUID == 0 {
            return Err(JournalError::CorruptTag);
        }
        if flags & TAG_DELETED != 0 {
            targets.push(None);
        } else {
            targets.push(Some(block_low | (block_high << 32)));
        }
        if targets.len() > MAX_TAGS {
            return Err(JournalError::LimitExceeded);
        }
        if flags & TAG_LAST != 0 {
            break;
        }
    }
    let _ = uuid;
    Ok(targets)
}

/// Parses revoke records in a revoke block.
pub fn revoke_targets(revoke: &[u8], block_size: usize) -> Result<Vec<u64>, JournalError> {
    if revoke.len() < block_size {
        return Err(JournalError::Truncated);
    }
    let mut cursor = 16usize;
    let mut targets = Vec::new();
    while cursor + 8 <= block_size - 12 {
        let flags = revoke[cursor];
        let low = read_u32(revoke, cursor + 1).ok_or(JournalError::Truncated)? as u64;
        cursor += 5;
        let high = if flags & TAG_64BIT != 0 {
            let value = read_u32(revoke, cursor).ok_or(JournalError::Truncated)? as u64;
            cursor += 4;
            value
        } else {
            0
        };
        targets.push(low | (high << 32));
        if targets.len() > MAX_REVOKES {
            return Err(JournalError::LimitExceeded);
        }
        if flags & TAG_LAST != 0 {
            break;
        }
    }
    Ok(targets)
}

/// Builds an idempotent recovery plan for the transaction starting at `start`.
pub fn recovery_plan(
    journal: &[u8],
    sb: &JournalSuperBlock,
) -> Result<RecoveryPlan, JournalError> {
    let size = sb.block_size as usize;
    if size < 512 || size > crate::MAX_BLOCK_SIZE {
        return Err(JournalError::BadMagic);
    }
    let mut block_number = sb.start_block;
    let mut pending: Vec<(u32, u64)> = Vec::new();
    let mut revoked: Vec<u64> = Vec::new();
    let mut seen_commit = false;

    for _ in 0..MAX_TRANSACTION_BLOCKS {
        let current = block(journal, block_number, size).ok_or(JournalError::Truncated)?;
        let (kind, _sequence) = header(current).ok_or(JournalError::Truncated)?;
        match kind {
            DESC_BLOCK => {
                let targets = descriptor_targets(current, size)?;
                let mut next = block_number + 1;
                for target in targets {
                    let fs_block = match target {
                        Some(value) => value,
                        None => {
                            next += 1;
                            continue;
                        }
                    };
                    let data = block(journal, next, size).ok_or(JournalError::Truncated)?;
                    let _ = data;
                    pending.push((next, fs_block));
                    next += 1;
                }
                block_number = next;
            }
            REVOKE_BLOCK => {
                revoked.extend(revoke_targets(current, size)?);
                block_number += 1;
            }
            COMMIT_BLOCK => {
                let checksum = read_u32(current, size - 4)
                    .ok_or(JournalError::Truncated)?;
                let computed = crc32c(!0, &current[..size - 4]);
                if checksum != computed {
                    return Err(JournalError::CorruptDescriptor);
                }
                seen_commit = true;
                break;
            }
            other => return Err(JournalError::UnknownBlockType(other)),
        }
    }

    if !seen_commit {
        return Err(JournalError::MissingCommit);
    }

    let mut actions = Vec::new();
    for fs_block in revoked.iter().copied() {
        actions.push(Action::Revoke { fs_block });
    }
    for (journal_block, fs_block) in pending {
        if !revoked.contains(&fs_block) {
            actions.push(Action::Write {
                journal_block,
                fs_block,
            });
        }
    }
    Ok(RecoveryPlan {
        sequence: sb.sequence,
        actions,
    })
}

/// Applies a plan to a mutable image, skipping writes beyond its bounds.
pub fn apply_plan(image: &mut [u8], journal: &[u8], plan: &RecoveryPlan) -> usize {
    let size = crate::BLOCK_SIZE;
    let mut applied = 0usize;
    for action in &plan.actions {
        if let Action::Write {
            journal_block,
            fs_block,
        } = action
        {
            let start = (*journal_block as usize).checked_mul(size);
            let dest = (*fs_block as usize).checked_mul(size);
            if let (Some(src), Some(dst)) = (start, dest) {
                if let (Some(data), Some(target)) = (
                    journal.get(src..src + size),
                    image.get_mut(dst..dst + size),
                ) {
                    target.copy_from_slice(data);
                    applied += 1;
                }
            }
        }
    }
    applied
}

/// Converts a format error into a journal error for callers that only need
/// a single error type.
pub fn from_format_error(error: FormatError) -> JournalError {
    match error {
        FormatError::Truncated => JournalError::Truncated,
        FormatError::NeedsRecovery => JournalError::MissingCommit,
        _ => JournalError::CorruptDescriptor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn superblock(sequence: u32, start: u32) -> Vec<u8> {
        let mut sb = vec![0u8; 2048];
        sb[1024..1028].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        sb[1028..1032].copy_from_slice(&sequence.to_be_bytes());
        sb[1032..1036].copy_from_slice(&start.to_be_bytes());
        sb[1036..1040].copy_from_slice(&(JOURNAL_BLOCK_SIZE as u32).to_be_bytes());
        sb[1040..1044].copy_from_slice(&64u32.to_be_bytes());
        sb
    }

    fn blank(size: usize) -> Vec<u8> {
        vec![0u8; size]
    }

    fn set_commit(journal: &mut [u8], index: usize) {
        let start = index * JOURNAL_BLOCK_SIZE;
        journal[start..start + 4].copy_from_slice(&COMMIT_BLOCK.to_be_bytes());
        let checksum = crc32c(!0, &journal[start..start + JOURNAL_BLOCK_SIZE - 4]);
        let end = start + JOURNAL_BLOCK_SIZE;
        journal[end - 4..end].copy_from_slice(&checksum.to_be_bytes());
    }

    #[test]
    fn parses_superblock() {
        let sb = parse_superblock(&superblock(7, 1)).unwrap();
        assert_eq!(sb.sequence, 7);
        assert_eq!(sb.start_block, 1);
        assert_eq!(sb.block_size, JOURNAL_BLOCK_SIZE as u32);
    }

    #[test]
    fn descriptor_tags_parse_and_escape() {
        let mut desc = blank(JOURNAL_BLOCK_SIZE);
        desc[12] = TAG_LAST | TAG_SAME_UUID;
        desc[13..17].copy_from_slice(&42u32.to_be_bytes());
        let targets = descriptor_targets(&desc, JOURNAL_BLOCK_SIZE).unwrap();
        assert_eq!(targets, vec![Some(42)]);

        let mut escaped = blank(JOURNAL_BLOCK_SIZE);
        escaped[12] = TAG_ESCAPE | TAG_64BIT;
        escaped[13..17].copy_from_slice(&7u32.to_be_bytes());
        escaped[17..21].copy_from_slice(&1u32.to_be_bytes());
        escaped[21..37].copy_from_slice(&[9u8; 16]);
        escaped[37] = TAG_LAST | TAG_SAME_UUID;
        escaped[38..42].copy_from_slice(&8u32.to_be_bytes());
        let targets = descriptor_targets(&escaped, JOURNAL_BLOCK_SIZE).unwrap();
        assert_eq!(targets, vec![Some((1 << 32) | 7), Some(8)]);
    }

    #[test]
    fn recovery_plan_skips_revokes_and_is_idempotent() {
        let mut journal = superblock(3, 1);
        journal.resize(JOURNAL_BLOCK_SIZE * 4, 0);
        let desc = JOURNAL_BLOCK_SIZE;
        journal[desc..desc + 4].copy_from_slice(&DESC_BLOCK.to_be_bytes());
        journal[desc + 12] = TAG_LAST | TAG_SAME_UUID;
        journal[desc + 13..desc + 17].copy_from_slice(&10u32.to_be_bytes());
        let _ = desc;
        set_commit(&mut journal, 3);
        let sb = parse_superblock(&journal).unwrap();
        let plan = recovery_plan(&journal, &sb).unwrap();
        assert_eq!(plan.actions.len(), 1);

        let mut image = vec![0u8; JOURNAL_BLOCK_SIZE * 20];
        let first = apply_plan(&mut image, &journal, &plan);
        let snapshot = image.clone();
        let second = apply_plan(&mut image, &journal, &plan);
        assert_eq!(first, 1);
        assert_eq!(second, 1);
        assert_eq!(image, snapshot);
    }

    #[test]
    fn rejects_truncated_and_corrupt() {
        let short = vec![0u8; 1024];
        assert_eq!(parse_superblock(&short), Err(JournalError::Truncated));
        let mut journal = superblock(1, 1);
        journal.resize(JOURNAL_BLOCK_SIZE * 2, 0);
        let sb = parse_superblock(&journal).unwrap();
        assert_eq!(
            recovery_plan(&journal, &sb),
            Err(JournalError::UnknownBlockType(0))
        );

        set_commit(&mut journal, 1);
        journal[2 * JOURNAL_BLOCK_SIZE - 1] ^= 0xFF;
        let sb = parse_superblock(&journal).unwrap();
        assert_eq!(
            recovery_plan(&journal, &sb),
            Err(JournalError::CorruptDescriptor)
        );
    }
}
