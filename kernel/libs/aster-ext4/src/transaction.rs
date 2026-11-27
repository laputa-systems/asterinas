// SPDX-License-Identifier: MPL-2.0

//! Bounded write-ahead transaction state machine for LC-19.
//!
//! A transaction reserves credits, collects ordered data blocks and revoke
//! records, then emits a JBD2 descriptor/data/commit sequence. The emitted
//! sequence is parseable by [`crate::jbd2::recovery_plan`], so the write path
//! and the recovery path share one on-disk contract. Exhausted log space or
//! a failed commit aborts the transaction into a read-only state; no partial
//! commit record is left behind.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    crc32c,
    jbd2::{
        COMMIT_BLOCK, DESC_BLOCK, JOURNAL_BLOCK_SIZE, JBD2_MAGIC, REVOKE_BLOCK, TAG_LAST,
        TAG_SAME_UUID,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxError {
    NoCredits,
    LogFull,
    AlreadyCommitted,
    Aborted,
    TruncatedJournal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxState {
    Running,
    Committing,
    Checkpointed,
    Aborted,
}

#[derive(Clone, Debug)]
struct PendingWrite {
    fs_block: u64,
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    sequence: u32,
    state: TxState,
    credits_used: u32,
    credits_reserved: u32,
    journal_blocks_used: usize,
    journal_blocks_total: usize,
    pending: Vec<PendingWrite>,
    revoked: Vec<u64>,
}

impl Transaction {
    pub fn begin(sequence: u32, journal_blocks_total: usize) -> Self {
        Self {
            sequence,
            state: TxState::Running,
            credits_used: 0,
            credits_reserved: 0,
            journal_blocks_used: 1,
            journal_blocks_total,
            pending: Vec::new(),
            revoked: Vec::new(),
        }
    }

    pub fn state(&self) -> TxState {
        self.state
    }

    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Reserves credits. Each ordered data block and each journal metadata
    /// block consumes one credit.
    pub fn reserve_credits(&mut self, credits: u32) -> Result<(), TxError> {
        if self.state != TxState::Running {
            return Err(TxError::Aborted);
        }
        let next = self
            .credits_reserved
            .checked_add(credits)
            .ok_or(TxError::NoCredits)?;
        let needed = next as usize + 2 + self.pending.len();
        if needed > self.journal_blocks_total {
            return Err(TxError::LogFull);
        }
        self.credits_reserved = next;
        Ok(())
    }

    pub fn add_ordered_data(&mut self, fs_block: u64, data: Vec<u8>) -> Result<(), TxError> {
        if self.state != TxState::Running {
            return Err(TxError::Aborted);
        }
        if self.credits_used >= self.credits_reserved {
            return Err(TxError::NoCredits);
        }
        if data.len() > JOURNAL_BLOCK_SIZE {
            return Err(TxError::LogFull);
        }
        self.credits_used += 1;
        self.pending.push(PendingWrite { fs_block, data });
        Ok(())
    }

    pub fn revoke(&mut self, fs_block: u64) -> Result<(), TxError> {
        if self.state != TxState::Running {
            return Err(TxError::Aborted);
        }
        if self.credits_used >= self.credits_reserved {
            return Err(TxError::NoCredits);
        }
        self.credits_used += 1;
        self.revoked.push(fs_block);
        Ok(())
    }

    /// Emits the journal image for this transaction. The buffer must be large
    /// enough for a superblock plus one descriptor, one revoke (when present),
    /// the ordered data blocks and one commit block.
    pub fn commit(&mut self, journal: &mut [u8]) -> Result<usize, TxError> {
        if self.state != TxState::Running {
            return Err(TxError::Aborted);
        }
        let blocks = 2 + self.pending.len() + usize::from(!self.revoked.is_empty()) + 1;
        let needed = blocks * JOURNAL_BLOCK_SIZE;
        if journal.len() < needed {
            return Err(TxError::TruncatedJournal);
        }
        if needed > self.journal_blocks_total * JOURNAL_BLOCK_SIZE {
            return Err(TxError::LogFull);
        }

        self.state = TxState::Committing;
        let sb = &mut journal[1024..2048];
        sb[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        sb[4..8].copy_from_slice(&self.sequence.to_be_bytes());
        sb[8..12].copy_from_slice(&1u32.to_be_bytes());
        sb[12..16].copy_from_slice(&(JOURNAL_BLOCK_SIZE as u32).to_be_bytes());

        let mut block = 1usize;
        let desc_start = block * JOURNAL_BLOCK_SIZE;
        let desc = &mut journal[desc_start..desc_start + JOURNAL_BLOCK_SIZE];
        desc[0..4].copy_from_slice(&DESC_BLOCK.to_be_bytes());
        for (index, write) in self.pending.iter().enumerate() {
            let offset = 12 + index * 12;
            let flags = if index + 1 == self.pending.len() {
                TAG_LAST | TAG_SAME_UUID
            } else {
                TAG_SAME_UUID
            };
            desc[offset] = flags;
            desc[offset + 1..offset + 5].copy_from_slice(&(write.fs_block as u32).to_be_bytes());
        }
        block += 1;

        for write in &self.pending {
            let start = block * JOURNAL_BLOCK_SIZE;
            journal[start..start + write.data.len()].copy_from_slice(&write.data);
            block += 1;
        }

        if !self.revoked.is_empty() {
            let revoke_start = block * JOURNAL_BLOCK_SIZE;
            let revoke = &mut journal[revoke_start..revoke_start + JOURNAL_BLOCK_SIZE];
            revoke[0..4].copy_from_slice(&REVOKE_BLOCK.to_be_bytes());
            for (index, fs_block) in self.revoked.iter().enumerate() {
                let offset = 16 + index * 5;
                revoke[offset] = if index + 1 == self.revoked.len() {
                    TAG_LAST
                } else {
                    0
                };
                revoke[offset + 1..offset + 5]
                    .copy_from_slice(&(*fs_block as u32).to_be_bytes());
            }
            block += 1;
        }

        let commit_start = block * JOURNAL_BLOCK_SIZE;
        journal[commit_start..commit_start + 4].copy_from_slice(&COMMIT_BLOCK.to_be_bytes());
        let checksum = crc32c(
            !0,
            &journal[commit_start..commit_start + JOURNAL_BLOCK_SIZE - 4],
        );
        let end = commit_start + JOURNAL_BLOCK_SIZE;
        journal[end - 4..end].copy_from_slice(&checksum.to_be_bytes());

        self.journal_blocks_used = block + 1;
        Ok(self.journal_blocks_used)
    }

    pub fn checkpoint(&mut self) -> TxState {
        if self.state == TxState::Committing {
            self.state = TxState::Checkpointed;
        }
        self.state
    }

    /// Aborts before commit, leaving no commit record. An already committed
    /// transaction cannot be aborted.
    pub fn abort(&mut self) -> TxState {
        if self.state == TxState::Running {
            self.state = TxState::Aborted;
        }
        self.state
    }

    pub fn journal_blocks_used(&self) -> usize {
        self.journal_blocks_used
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jbd2::{parse_superblock, recovery_plan};

    #[test]
    fn commit_record_is_parseable_by_recovery() {
        let mut tx = Transaction::begin(7, 16);
        tx.reserve_credits(2).unwrap();
        tx.add_ordered_data(10, vec![0xAB; JOURNAL_BLOCK_SIZE]).unwrap();
        let mut journal = vec![0u8; 8 * JOURNAL_BLOCK_SIZE];
        let blocks = tx.commit(&mut journal).unwrap();
        assert_eq!(blocks, 4);
        assert_eq!(tx.checkpoint(), TxState::Checkpointed);

        let sb = parse_superblock(&journal).unwrap();
        assert_eq!(sb.sequence, 7);
        let plan = recovery_plan(&journal, &sb).unwrap();
        assert_eq!(plan.actions.len(), 1);
    }

    #[test]
    fn revoke_record_is_parseable_by_recovery() {
        let mut tx = Transaction::begin(8, 16);
        tx.reserve_credits(2).unwrap();
        tx.add_ordered_data(10, vec![0xCD; JOURNAL_BLOCK_SIZE]).unwrap();
        tx.revoke(10).unwrap();
        let mut journal = vec![0u8; 8 * JOURNAL_BLOCK_SIZE];
        tx.commit(&mut journal).unwrap();
        let sb = parse_superblock(&journal).unwrap();
        let plan = recovery_plan(&journal, &sb).unwrap();
        assert_eq!(plan.actions.len(), 1);
    }

    #[test]
    fn credits_and_log_space_are_bounded() {
        let mut tx = Transaction::begin(1, 4);
        assert_eq!(tx.reserve_credits(8), Err(TxError::LogFull));
        assert_eq!(tx.add_ordered_data(1, Vec::new()), Err(TxError::NoCredits));
        tx.reserve_credits(1).unwrap();
        tx.add_ordered_data(1, vec![0u8; JOURNAL_BLOCK_SIZE]).unwrap();
        assert_eq!(tx.add_ordered_data(2, Vec::new()), Err(TxError::NoCredits));
    }

    #[test]
    fn abort_before_commit_leaves_no_commit_record() {
        let mut tx = Transaction::begin(9, 16);
        assert_eq!(tx.abort(), TxState::Aborted);
        let mut journal = vec![0u8; 8 * JOURNAL_BLOCK_SIZE];
        assert_eq!(tx.commit(&mut journal), Err(TxError::Aborted));
        assert!(journal.iter().all(|byte| *byte == 0));
    }
}
