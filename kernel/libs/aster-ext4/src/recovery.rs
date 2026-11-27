// SPDX-License-Identifier: MPL-2.0

//! Mount-time JBD2 recovery composition.
//!
//! Recovery is attempted only for images the format layer reports as
//! unclean or needing recovery. The filesystem state bits are cleared only
//! after the replayed image passes a fresh format analysis; a failed or
//! incomplete replay therefore never marks a broken filesystem clean.

extern crate alloc;

use crate::jbd2::{self, JournalError, JournalSuperBlock};
use crate::{Error, SUPER_BLOCK_OFFSET, analyze, INCOMPAT_RECOVERY, STATE_NEEDS_RECOVERY, STATE_UNCLEAN};

pub const SB_STATE: usize = 0x3A;
pub const SB_FEATURE_INCOMPAT: usize = 0x60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountError {
    Unrecoverable(Error),
    Journal(JournalError),
    RecoveryDidNotClean,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountOutcome {
    Clean,
    Recovered { blocks_replayed: usize },
}

fn set_clean(image: &mut [u8]) -> Result<(), MountError> {
    let sb = image
        .get_mut(SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024)
        .ok_or(MountError::Unrecoverable(Error::Truncated))?;
    let state = u16::from_le_bytes([sb[SB_STATE], sb[SB_STATE + 1]]);
    let state = state & !(STATE_NEEDS_RECOVERY | STATE_UNCLEAN);
    sb[SB_STATE..SB_STATE + 2].copy_from_slice(&state.to_le_bytes());
    let incompat = u32::from_le_bytes(
        sb[SB_FEATURE_INCOMPAT..SB_FEATURE_INCOMPAT + 4]
            .try_into()
            .map_err(|_| MountError::Unrecoverable(Error::Truncated))?,
    );
    let incompat = incompat & !INCOMPAT_RECOVERY;
    sb[SB_FEATURE_INCOMPAT..SB_FEATURE_INCOMPAT + 4].copy_from_slice(&incompat.to_le_bytes());
    Ok(())
}

fn needs_recovery(error: Error) -> bool {
    matches!(error, Error::NeedsRecovery | Error::Unclean)
}

/// Replays the journal once and returns the number of data blocks written.
/// Does not modify the filesystem state bits.
pub fn replay_once(image: &mut [u8], journal: &[u8]) -> Result<usize, MountError> {
    let sb: JournalSuperBlock = jbd2::parse_superblock(journal).map_err(MountError::Journal)?;
    let plan = jbd2::recovery_plan(journal, &sb).map_err(MountError::Journal)?;
    Ok(jbd2::apply_plan(image, journal, &plan))
}

/// Mount-time entry point: replays only when required, and marks the image
/// clean only after a fresh analysis succeeds.
pub fn mount(image: &mut [u8], journal: &[u8]) -> Result<MountOutcome, MountError> {
    match analyze(image) {
        Ok(_) => return Ok(MountOutcome::Clean),
        Err(error) if !needs_recovery(error) => return Err(MountError::Unrecoverable(error)),
        Err(_) => {}
    }

    let blocks_replayed = replay_once(image, journal)?;

    let mut probe = image.to_vec();
    set_clean(&mut probe)?;
    analyze(&probe).map_err(MountError::Unrecoverable)?;

    set_clean(image)?;
    analyze(image).map_err(|_| MountError::RecoveryDidNotClean)?;
    Ok(MountOutcome::Recovered { blocks_replayed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jbd2::{
        COMMIT_BLOCK, DESC_BLOCK, JOURNAL_BLOCK_SIZE, JBD2_MAGIC, TAG_LAST, TAG_SAME_UUID,
    };
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

    fn mark_needs_recovery(image: &mut [u8]) {
        let sb = &mut image[SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024];
        let state = u16::from_le_bytes([sb[SB_STATE], sb[SB_STATE + 1]])
            | STATE_NEEDS_RECOVERY
            | STATE_UNCLEAN;
        sb[SB_STATE..SB_STATE + 2].copy_from_slice(&state.to_le_bytes());
        let incompat = u32::from_le_bytes(
            sb[SB_FEATURE_INCOMPAT..SB_FEATURE_INCOMPAT + 4]
                .try_into()
                .unwrap(),
        ) | INCOMPAT_RECOVERY;
        sb[SB_FEATURE_INCOMPAT..SB_FEATURE_INCOMPAT + 4]
            .copy_from_slice(&incompat.to_le_bytes());
    }

    fn valid_journal() -> Vec<u8> {
        let mut journal = vec![0u8; JOURNAL_BLOCK_SIZE * 4];
        let sb = &mut journal[1024..2048];
        sb[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        sb[4..8].copy_from_slice(&1u32.to_be_bytes());
        sb[8..12].copy_from_slice(&1u32.to_be_bytes());
        sb[12..16].copy_from_slice(&(JOURNAL_BLOCK_SIZE as u32).to_be_bytes());
        let desc = JOURNAL_BLOCK_SIZE;
        journal[desc..desc + 4].copy_from_slice(&DESC_BLOCK.to_be_bytes());
        journal[desc + 12] = TAG_LAST | TAG_SAME_UUID;
        journal[desc + 13..desc + 17].copy_from_slice(&10u32.to_be_bytes());
        let commit = JOURNAL_BLOCK_SIZE * 3;
        journal[commit..commit + 4].copy_from_slice(&COMMIT_BLOCK.to_be_bytes());
        let checksum = crate::crc32c(!0, &journal[commit..commit + JOURNAL_BLOCK_SIZE - 4]);
        journal[commit + JOURNAL_BLOCK_SIZE - 4..commit + JOURNAL_BLOCK_SIZE]
            .copy_from_slice(&checksum.to_be_bytes());
        journal
    }

    #[test]
    fn clean_fixture_needs_no_recovery() {
        let mut image = fixture("basic");
        assert_eq!(mount(&mut image, &[]), Ok(MountOutcome::Clean));
    }

    #[test]
    fn replays_and_marks_clean() {
        let mut image = fixture("basic");
        mark_needs_recovery(&mut image);
        assert!(analyze(&image).is_err());
        let journal = valid_journal();
        assert_eq!(
            mount(&mut image, &journal),
            Ok(MountOutcome::Recovered { blocks_replayed: 1 })
        );
        assert!(analyze(&image).is_ok());
        assert_eq!(mount(&mut image, &journal), Ok(MountOutcome::Clean));
    }

    #[test]
    fn interrupted_replay_survives_mount() {
        let mut image = fixture("basic");
        mark_needs_recovery(&mut image);
        let journal = valid_journal();
        let sb = jbd2::parse_superblock(&journal).unwrap();
        let plan = jbd2::recovery_plan(&journal, &sb).unwrap();
        jbd2::apply_plan(&mut image, &journal, &plan);
        jbd2::apply_plan(&mut image, &journal, &plan);
        assert_eq!(
            mount(&mut image, &journal),
            Ok(MountOutcome::Recovered { blocks_replayed: 1 })
        );
        assert!(analyze(&image).is_ok());
    }

    #[test]
    fn failed_replay_never_marks_clean() {
        let mut image = fixture("basic");
        mark_needs_recovery(&mut image);
        let mut journal = valid_journal();
        let commit = JOURNAL_BLOCK_SIZE * 3;
        journal[commit + JOURNAL_BLOCK_SIZE - 1] ^= 0xFF;
        assert!(mount(&mut image, &journal).is_err());
        assert!(analyze(&image).is_err());
    }

    #[test]
    fn missing_journal_never_marks_clean() {
        let mut image = fixture("basic");
        mark_needs_recovery(&mut image);
        assert!(matches!(
            mount(&mut image, &[]),
            Err(MountError::Journal(JournalError::Truncated))
        ));
        assert!(analyze(&image).is_err());
    }
}
