// SPDX-License-Identifier: MPL-2.0

use super::Vec;

use super::{block, parse_internal_superblock, read_u32, InternalJournalSuperblock, InternalSuperblockError, JBD2_MAGIC, MAX_REVOKES, MAX_TAGS, MAX_TRANSACTION_BLOCKS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Superblock(InternalSuperblockError),
    Unsupported,
    Truncated,
    Invalid,
    Checksum,
    LimitExceeded,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid journal transaction: {self:?}")
    }
}

impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Write {
    pub journal_block: u32,
    pub fs_block: u64,
    pub escaped: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub sequence: u32,
    pub writes: Vec<Write>,
    pub revokes: Vec<u64>,
}

fn crc32_be(mut crc: u32, data: &[u8]) -> u32 {
    for byte in data {
        crc ^= u32::from(*byte) << 24;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc & 0x8000_0000 != 0 { 0x04c1_1db7 } else { 0 };
        }
    }
    crc
}

fn checksum_block(seed: u32, data: &[u8], offset: usize) -> u32 {
    let crc = crate::ext4_crc32c(seed, &data[..offset]);
    let crc = crate::ext4_crc32c(crc, &[0; 4]);
    crate::ext4_crc32c(crc, &data[offset + 4..])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetWidth {
    Bits32,
    Bits64,
}

#[derive(Debug)]
pub struct MetadataBlock<'a> {
    pub fs_block: u64,
    pub data: &'a [u8],
}

/// Encodes one v3 transaction as a descriptor, payload blocks, and commit.
///
/// # Errors
/// Returns an error if the blocks, targets, or descriptor exceed the supported bounds.
pub fn encode_v3_transaction(
    block_size: usize,
    uuid: &[u8; 16],
    sequence: u32,
    filesystem_blocks: u64,
    target_width: TargetWidth,
    metadata: &[MetadataBlock<'_>],
) -> Result<Vec<Vec<u8>>, Error> {
    if !(1024..=crate::MAX_BLOCK_SIZE).contains(&block_size) || !block_size.is_power_of_two()
        || metadata.is_empty()
    {
        return Err(Error::Invalid);
    }
    if metadata.len() > MAX_TAGS || metadata.len() + 2 > MAX_TRANSACTION_BLOCKS
        || metadata.len() > (block_size - 32) / 16
    {
        return Err(Error::LimitExceeded);
    }
    for entry in metadata {
        if entry.data.len() != block_size || entry.fs_block >= filesystem_blocks
            || (target_width == TargetWidth::Bits32 && entry.fs_block > u64::from(u32::MAX))
        {
            return Err(Error::Invalid);
        }
    }
    let seed = crate::ext4_crc32c(!0, uuid);
    let payload_seed = crate::ext4_crc32c(seed, &sequence.to_be_bytes());
    let mut descriptor = super::alloc::vec![0; block_size];
    descriptor[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    descriptor[4..8].copy_from_slice(&1u32.to_be_bytes());
    descriptor[8..12].copy_from_slice(&sequence.to_be_bytes());
    let mut blocks = Vec::with_capacity(metadata.len() + 2);
    for (index, entry) in metadata.iter().enumerate() {
        let mut payload = entry.data.to_vec();
        let escaped = payload[..4] == JBD2_MAGIC.to_be_bytes();
        if escaped { payload[..4].fill(0); }
        let flags = u32::from(escaped) | if index == 0 { 0 } else { 2 }
            | if index + 1 == metadata.len() { 8 } else { 0 };
        let offset = 12 + index * 16 + if index == 0 { 0 } else { 16 };
        descriptor[offset..offset + 4].copy_from_slice(&(entry.fs_block as u32).to_be_bytes());
        descriptor[offset + 4..offset + 8].copy_from_slice(&flags.to_be_bytes());
        descriptor[offset + 8..offset + 12].copy_from_slice(&((entry.fs_block >> 32) as u32).to_be_bytes());
        let checksum = crate::ext4_crc32c(payload_seed, &payload);
        descriptor[offset + 12..offset + 16].copy_from_slice(&checksum.to_be_bytes());
        if index == 0 { descriptor[offset + 16..offset + 32].copy_from_slice(uuid); }
        blocks.push(payload);
    }
    let checksum = checksum_block(seed, &descriptor, block_size - 4);
    descriptor[block_size - 4..].copy_from_slice(&checksum.to_be_bytes());
    blocks.insert(0, descriptor);
    let mut commit = super::alloc::vec![0; block_size];
    commit[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    commit[4..8].copy_from_slice(&2u32.to_be_bytes());
    commit[8..12].copy_from_slice(&sequence.to_be_bytes());
    let checksum = checksum_block(seed, &commit, 16);
    commit[16..20].copy_from_slice(&checksum.to_be_bytes());
    blocks.push(commit);
    Ok(blocks)
}

/// Validates and returns the first committed transaction in an internal journal.
/// The caller must account for later transactions and revokes before replaying writes.
/// Escaped writes require restoring the JBD2 magic at the start of the payload.
///
/// # Errors
/// Returns an error for unsupported, incomplete, or corrupt journal data.
pub fn first_transaction(
    journal: &[u8],
    uuid: &[u8; 16],
    filesystem_blocks: u64,
) -> Result<Transaction, Error> {
    let sb = checked_superblock(journal, uuid)?;
    let mut transaction = parse_transaction(journal, uuid, filesystem_blocks, &sb, sb.start, sb.sequence,
        (sb.max_len - sb.first) as usize)?.ok_or(Error::Invalid)?.0;
    transaction.writes.retain(|write| !transaction.revokes.contains(&write.fs_block));
    Ok(transaction)
}

/// Scans committed transactions in journal order, preserving writes and revokes for recovery.
/// A missing or stale header ends the scan; matching malformed records return an error.
///
/// # Errors
/// Returns an error for unsupported or corrupt journal data or exceeded bounds.
pub fn scan_transactions(
    journal: &[u8],
    uuid: &[u8; 16],
    filesystem_blocks: u64,
) -> Result<Vec<Transaction>, Error> {
    let sb = checked_superblock(journal, uuid)?;
    let mut position = sb.start;
    let mut sequence = sb.sequence;
    let ring_blocks = (sb.max_len - sb.first) as usize;
    let mut remaining = ring_blocks.min(MAX_TRANSACTION_BLOCKS);
    let mut writes = 0usize;
    let mut revokes = 0usize;
    let mut transactions = Vec::new();
    while remaining > 0 {
        let Some((transaction, next_position, consumed)) = parse_transaction(
            journal, uuid, filesystem_blocks, &sb, position, sequence, remaining,
        )? else { return Ok(transactions) };
        writes += transaction.writes.len();
        revokes += transaction.revokes.len();
        if writes > MAX_TAGS || revokes > MAX_REVOKES { return Err(Error::LimitExceeded); }
        transactions.push(transaction);
        remaining -= consumed;
        position = next_position;
        sequence = sequence.wrapping_add(1);
    }
    if ring_blocks > MAX_TRANSACTION_BLOCKS { return Err(Error::LimitExceeded); }
    Ok(transactions)
}

fn checked_superblock(journal: &[u8], uuid: &[u8; 16]) -> Result<InternalJournalSuperblock, Error> {
    let sb = parse_internal_superblock(journal, journal.len() as u64, uuid).map_err(Error::Superblock)?;
    if sb.errno != 0 || sb.start == 0 || sb.feature_incompat & 8 != 0
        || (sb.feature_compat & 1 == 0 && sb.feature_incompat & 16 == 0)
    {
        return Err(Error::Unsupported);
    }
    Ok(sb)
}

fn parse_transaction(
    journal: &[u8],
    uuid: &[u8; 16],
    filesystem_blocks: u64,
    sb: &InternalJournalSuperblock,
    start: u32,
    sequence: u32,
    available: usize,
) -> Result<Option<(Transaction, u32, usize)>, Error> {
    let size = sb.block_size as usize;
    let v3 = sb.feature_incompat & 16 != 0;
    let wide = sb.feature_incompat & 2 != 0;
    let seed = crate::ext4_crc32c(!0, uuid);
    let mut old_crc = !0;
    let mut position = start;
    let mut consumed = 0usize;
    let mut writes = Vec::new();
    let mut revokes = Vec::new();
    let mut saw_record = false;
    let next = |n: u32| if n + 1 == sb.max_len { sb.first } else { n + 1 };
    loop {
        if consumed >= MAX_TRANSACTION_BLOCKS || consumed >= available {
            return Err(Error::LimitExceeded);
        }
        let current = block(journal, position, size).ok_or(Error::Truncated)?;
        consumed += 1;
        let magic = read_u32(current, 0);
        let record_sequence = read_u32(current, 8);
        if magic != Some(JBD2_MAGIC) || record_sequence != Some(sequence) {
            if magic != Some(JBD2_MAGIC) && record_sequence == Some(sequence)
                && current.iter().any(|byte| *byte != 0)
            {
                return Err(Error::Invalid);
            }
            return Ok(None);
        }
        match read_u32(current, 4).ok_or(Error::Truncated)? {
            1 => {
                saw_record = true;
                if v3 && read_u32(current, size - 4) != Some(checksum_block(seed, current, size - 4)) {
                    return Err(Error::Checksum);
                }
                if !v3 { old_crc = crc32_be(old_crc, current); }
                let end = size - if v3 { 4 } else { 0 };
                let mut cursor = 12;
                let mut tags = Vec::new();
                let mut have_uuid = false;
                loop {
                    let tag_size = if v3 { 16 } else if wide { 12 } else { 8 };
                    if cursor + tag_size > end { return Err(Error::Invalid); }
                    let low = read_u32(current, cursor).ok_or(Error::Truncated)?;
                    let flags = if v3 { read_u32(current, cursor + 4).ok_or(Error::Truncated)? } else {
                        u32::from(u16::from_be_bytes([current[cursor + 6], current[cursor + 7]]))
                    };
                    if flags & !0xb != 0 { return Err(Error::Unsupported); }
                    let high = if v3 || wide { read_u32(current, cursor + 8).ok_or(Error::Truncated)? } else { 0 };
                    if !wide && high != 0 { return Err(Error::Invalid); }
                    let checksum = if v3 { read_u32(current, cursor + 12).ok_or(Error::Truncated)? } else { 0 };
                    cursor += tag_size;
                    if flags & 2 == 0 {
                        if cursor + 16 > end {
                            return Err(Error::Invalid);
                        }
                        let tag_uuid = &current[cursor..cursor + 16];
                        if tag_uuid != uuid && tag_uuid != [0; 16] {
                            return Err(Error::Invalid);
                        }
                        have_uuid = true;
                        cursor += 16;
                    } else if !have_uuid {
                        return Err(Error::Invalid);
                    }
                    let target = u64::from(low) | (u64::from(high) << 32);
                    if target >= filesystem_blocks {
                        return Err(Error::Invalid);
                    }
                    tags.push((target, flags, checksum));
                    if writes.len() + tags.len() > MAX_TAGS { return Err(Error::LimitExceeded); }
                    if flags & 8 != 0 { break; }
                }
                for (fs_block, flags, checksum) in tags {
                    position = next(position);
                    consumed += 1;
                    if consumed > MAX_TRANSACTION_BLOCKS || consumed >= available { return Err(Error::LimitExceeded); }
                    let data = block(journal, position, size).ok_or(Error::Truncated)?;
                    if flags & 1 != 0 && data[..4] != [0; 4] { return Err(Error::Invalid); }
                    if v3 {
                        let crc = crate::ext4_crc32c(seed, &sequence.to_be_bytes());
                        if checksum != crate::ext4_crc32c(crc, data) { return Err(Error::Checksum); }
                    } else { old_crc = crc32_be(old_crc, data); }
                    writes.push(Write { journal_block: position, fs_block, escaped: flags & 1 != 0 });
                }
            }
            5 => {
                saw_record = true;
                if !v3 || sb.feature_incompat & 1 == 0 { return Err(Error::Unsupported); }
                if v3 && read_u32(current, size - 4) != Some(checksum_block(seed, current, size - 4)) { return Err(Error::Checksum); }
                let count = read_u32(current, 12).ok_or(Error::Truncated)? as usize;
                let width = if wide { 8 } else { 4 };
                if count < 16 || count > size - if v3 { 4 } else { 0 } || (count - 16) % width != 0 { return Err(Error::Invalid); }
                for offset in (16..count).step_by(width) {
                    let first = u64::from(read_u32(current, offset).ok_or(Error::Truncated)?);
                    let target = if wide { (first << 32) | u64::from(read_u32(current, offset + 4).ok_or(Error::Truncated)?) } else { first };
                    if target >= filesystem_blocks {
                        return Err(Error::Invalid);
                    }
                    revokes.push(target);
                    if revokes.len() > MAX_REVOKES { return Err(Error::LimitExceeded); }
                }
            }
            2 => {
                if !saw_record { return Err(Error::Invalid); }
                let expected = read_u32(current, 16).ok_or(Error::Truncated)?;
                if v3 {
                    if current[12] != 0 || current[13] != 0 || expected != checksum_block(seed, current, 16) { return Err(Error::Checksum); }
                } else if current[12] != 1 || current[13] != 4 || expected != old_crc { return Err(Error::Checksum); }
                return Ok(Some((Transaction { sequence, writes, revokes }, next(position), consumed)));
            }
            _ => return Err(Error::Invalid),
        }
        position = next(position);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn fixture(name: &str) -> Vec<u8> {
        let mut path = std::env::var_os("ASTER_EXT4_FIXTURES").map(PathBuf::from).unwrap_or_else(|| {
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            for _ in 0..3 { path.pop(); }
            path.push("target/qualification/inputs/ext4");
            path
        });
        path.push(name);
        fs::read(path).unwrap()
    }

    fn journal(image: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let uuid = image[1024 + 0x68..1024 + 0x78].try_into().unwrap();
        let geometry = crate::reader::geometry(image).unwrap();
        let inode = crate::reader::read_inode(image, &geometry, 8).unwrap();
        (crate::reader::read_file(image, &geometry, &inode).unwrap(), uuid)
    }

    #[test]
    #[ignore = "requires the independently generated fixtures from build-journal.sh"]
    fn genuine_committed_transactions_and_corruption() {
        for (dirty, clean, target) in [("journal-v1.ext4", "basic.ext4", 1194), ("journal-v3.ext4", "large-address.ext4", 1195)] {
            let image = fixture(dirty);
            let (mut data, uuid) = journal(&image);
            let transaction = first_transaction(&data, &uuid, 4096).unwrap();
            assert_eq!(transaction.sequence, 1);
            assert_eq!(transaction.writes, [Write { journal_block: 2, fs_block: target, escaped: false }]);
            let clean_image = fixture(clean);
            let mut expected = clean_image[target as usize * 4096..(target as usize + 1) * 4096].to_vec();
            expected[0] = b'P';
            assert_eq!(&data[8192..12288], expected);
            for offset in [4096, 4096 + 12, 8192, 12288 + 16] {
                data[offset] ^= 1;
                assert!(first_transaction(&data, &uuid, 4096).is_err(), "{dirty} offset {offset}");
                data[offset] ^= 1;
            }
            assert!(first_transaction(&data[..12288], &uuid, 4096).is_err());
            assert_eq!(first_transaction(&data, &uuid, target), Err(Error::Invalid));
        }
    }
}

#[cfg(test)]
mod edge_tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn v3() -> (Vec<u8>, [u8; 16]) {
        let mut path = std::env::var_os("ASTER_EXT4_FIXTURES").map(PathBuf::from).unwrap_or_else(|| {
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            for _ in 0..3 { path.pop(); }
            path.push("target/qualification/inputs/ext4");
            path
        });
        path.push("journal-v3.ext4");
        let image = fs::read(path).unwrap();
        let uuid = image[0x468..0x478].try_into().unwrap();
        let geometry = crate::reader::geometry(&image).unwrap();
        let inode = crate::reader::read_inode(&image, &geometry, 8).unwrap();
        (crate::reader::read_file(&image, &geometry, &inode).unwrap(), uuid)
    }

    fn put_transaction(journal: &mut [u8], uuid: &[u8; 16], position: usize, sequence: u32, target: u64) {
        let payload = [7; 4096];
        let blocks = encode_v3_transaction(4096, uuid, sequence, 4096, TargetWidth::Bits64,
            &[MetadataBlock { fs_block: target, data: &payload }]).unwrap();
        for (index, block) in blocks.iter().enumerate() {
            let offset = (position + index) * 4096;
            journal[offset..offset + 4096].copy_from_slice(block);
        }
    }

    #[test]
    #[ignore = "requires the independently generated fixtures from build-journal.sh"]
    fn scans_committed_transactions_and_stops_at_incomplete_or_stale_tail() {
        let (mut journal, uuid) = v3();
        put_transaction(&mut journal, &uuid, 4, 2, 1200);
        let transactions = scan_transactions(&journal, &uuid, 4096).unwrap();
        assert_eq!(transactions.len(), 2);
        assert_eq!(transactions[0].sequence, 1);
        assert_eq!(transactions[1].sequence, 2);
        assert_eq!(transactions[1].writes[0].fs_block, 1200);
        journal[6 * 4096..7 * 4096].fill(0);
        assert_eq!(scan_transactions(&journal, &uuid, 4096).unwrap().len(), 1);
        put_transaction(&mut journal, &uuid, 4, 7, 1200);
        assert_eq!(scan_transactions(&journal, &uuid, 4096).unwrap().len(), 1);
        put_transaction(&mut journal, &uuid, 4, 2, 1200);
        journal[4 * 4096 + 20] ^= 1;
        assert_eq!(scan_transactions(&journal, &uuid, 4096), Err(Error::Checksum));
    }

    #[test]
    #[ignore = "requires the independently generated fixtures from build-journal.sh"]
    fn scans_sequence_wrap() {
        let (mut journal, uuid) = v3();
        journal[0x18..0x1c].copy_from_slice(&u32::MAX.to_be_bytes());
        let checksum = checksum_block(!0, &journal[..1024], 0xfc);
        journal[0xfc..0x100].copy_from_slice(&checksum.to_be_bytes());
        put_transaction(&mut journal, &uuid, 1, u32::MAX, 1195);
        put_transaction(&mut journal, &uuid, 4, 0, 1200);
        let transactions = scan_transactions(&journal, &uuid, 4096).unwrap();
        assert_eq!(transactions.iter().map(|tx| tx.sequence).collect::<Vec<_>>(), [u32::MAX, 0]);
    }

    fn tail(data: &mut [u8], seed: u32) {
        let offset = data.len() - 4;
        let checksum = checksum_block(seed, data, offset);
        data[offset..].copy_from_slice(&checksum.to_be_bytes());
    }

    #[test]
    #[ignore = "requires the independently generated fixtures from build-journal.sh"]
    fn wraps_and_restores_escaped_payload() {
        let (mut journal, uuid) = v3();
        let size = 4096;
        let seed = crate::ext4_crc32c(!0, &uuid);
        journal.copy_within(size..2 * size, 1023 * size);
        journal.copy_within(2 * size..3 * size, size);
        journal.copy_within(3 * size..4 * size, 2 * size);
        journal[0x1c..0x20].copy_from_slice(&1023u32.to_be_bytes());
        let sb_crc = checksum_block(!0, &journal[..1024], 0xfc);
        journal[0xfc..0x100].copy_from_slice(&sb_crc.to_be_bytes());
        journal[size..size + 4].fill(0);
        let crc = crate::ext4_crc32c(crate::ext4_crc32c(seed, &1u32.to_be_bytes()), &journal[size..2 * size]);
        let desc = &mut journal[1023 * size..1024 * size];
        desc[16..20].copy_from_slice(&9u32.to_be_bytes());
        desc[24..28].copy_from_slice(&crc.to_be_bytes());
        tail(desc, seed);
        let tx = first_transaction(&journal, &uuid, 4096).unwrap();
        assert_eq!(tx.writes, [Write { journal_block: 1, fs_block: 1195, escaped: true }]);
        assert_eq!(scan_transactions(&journal, &uuid, 4096).unwrap(), [tx]);
        let desc = &mut journal[1023 * size..1024 * size];
        desc[28] = 1;
        tail(desc, seed);
        assert_eq!(first_transaction(&journal, &uuid, 4096), Err(Error::Invalid));
        let desc = &mut journal[1023 * size..1024 * size];
        desc[28] = 0;
        tail(desc, seed);
        journal[size] = 1;
        assert!(first_transaction(&journal, &uuid, 4096).is_err());
    }

    #[test]
    #[ignore = "requires the independently generated fixtures from build-journal.sh"]
    fn decodes_wide_revokes_and_rejects_invalid_counts() {
        let (mut journal, uuid) = v3();
        let size = 4096;
        let seed = crate::ext4_crc32c(!0, &uuid);
        journal[0x2b] |= 1;
        let sb_crc = checksum_block(!0, &journal[..1024], 0xfc);
        journal[0xfc..0x100].copy_from_slice(&sb_crc.to_be_bytes());
        journal.copy_within(3 * size..4 * size, 4 * size);
        let revoke = &mut journal[3 * size..4 * size];
        revoke.fill(0);
        revoke[0..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        revoke[4..8].copy_from_slice(&5u32.to_be_bytes());
        revoke[8..12].copy_from_slice(&1u32.to_be_bytes());
        revoke[12..16].copy_from_slice(&24u32.to_be_bytes());
        revoke[16..24].copy_from_slice(&1195u64.to_be_bytes());
        tail(revoke, seed);
        let tx = first_transaction(&journal, &uuid, 4096).unwrap();
        assert!(tx.writes.is_empty());
        assert_eq!(tx.revokes, [1195]);
        let transactions = scan_transactions(&journal, &uuid, 4096).unwrap();
        assert_eq!(transactions[0].writes[0].fs_block, 1195);
        assert_eq!(transactions[0].revokes, [1195]);
        let revoke = &mut journal[3 * size..4 * size];
        revoke[12..16].copy_from_slice(&23u32.to_be_bytes());
        tail(revoke, seed);
        assert_eq!(first_transaction(&journal, &uuid, 4096), Err(Error::Invalid));
    }
}

#[cfg(test)]
mod encoder_tests {
    use super::*;
    use std::{fs, path::PathBuf};

    #[test]
    fn rejects_invalid_inputs_and_encodes_escaped_blocks() {
        let uuid = [1; 16];
        let mut data = super::super::alloc::vec![7; 1024];
        data[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
        let entry = MetadataBlock { fs_block: 4, data: &data };
        let blocks = encode_v3_transaction(1024, &uuid, 9, 10, TargetWidth::Bits32, &[entry]).unwrap();
        assert_eq!(&blocks[1][..4], &[0; 4]);
        assert_eq!(read_u32(&blocks[0], 16), Some(9));
        let checksum_seed = crate::ext4_crc32c(crate::ext4_crc32c(!0, &uuid), &9u32.to_be_bytes());
        assert_eq!(read_u32(&blocks[0], 24), Some(crate::ext4_crc32c(checksum_seed, &blocks[1])));
        let entries = [MetadataBlock { fs_block: 4, data: &data }, MetadataBlock { fs_block: (1 << 32) + 5, data: &data }];
        let blocks = encode_v3_transaction(1024, &uuid, 9, u64::MAX, TargetWidth::Bits64, &entries).unwrap();
        assert_eq!(read_u32(&blocks[0], 16), Some(1));
        assert_eq!(read_u32(&blocks[0], 48), Some(11));
        assert_eq!(read_u32(&blocks[0], 52), Some(1));
        let entries = [MetadataBlock { fs_block: 4, data: &data }];
        assert_eq!(encode_v3_transaction(1000, &uuid, 9, 10, TargetWidth::Bits32, &entries).unwrap_err(), Error::Invalid);
        assert!(encode_v3_transaction(1024, &[0; 16], 9, 10, TargetWidth::Bits32, &entries).is_ok());
        assert_eq!(encode_v3_transaction(1024, &uuid, 9, 10, TargetWidth::Bits32, &[]).unwrap_err(), Error::Invalid);
        let entry = MetadataBlock { fs_block: 10, data: &data };
        assert_eq!(encode_v3_transaction(1024, &uuid, 9, 10, TargetWidth::Bits32, &[entry]).unwrap_err(), Error::Invalid);
        let entry = MetadataBlock { fs_block: 1 << 32, data: &data };
        assert_eq!(encode_v3_transaction(1024, &uuid, 9, u64::MAX, TargetWidth::Bits32, &[entry]).unwrap_err(), Error::Invalid);
        let entry = MetadataBlock { fs_block: 1, data: &data[..1023] };
        assert_eq!(encode_v3_transaction(1024, &uuid, 9, 10, TargetWidth::Bits32, &[entry]).unwrap_err(), Error::Invalid);
        let entries: Vec<_> = (0..63).map(|_| MetadataBlock { fs_block: 1, data: &data }).collect();
        assert_eq!(encode_v3_transaction(1024, &uuid, 9, 10, TargetWidth::Bits32, &entries).unwrap_err(), Error::LimitExceeded);
    }

    #[test]
    #[ignore = "requires the checked journal-v3.ext4 fixture"]
    fn emit_v3_fixture_for_independent_replay() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let input = root.join("target/qualification/inputs/ext4");
        let mut image = fs::read(input.join("journal-v3.ext4")).unwrap();
        let uuid: [u8; 16] = image[0x468..0x478].try_into().unwrap();
        let geometry = crate::reader::geometry(&image).unwrap();
        let inode = crate::reader::read_inode(&image, &geometry, 8).unwrap();
        let journal = crate::reader::read_file(&image, &geometry, &inode).unwrap();
        let sb = parse_internal_superblock(&journal, journal.len() as u64, &uuid).unwrap();
        assert_eq!(sb.feature_incompat & 0x12, 0x12);
        let old = first_transaction(&journal, &uuid, geometry.blocks_count).unwrap();
        assert_eq!(old.writes.len(), 1);
        let target = old.writes[0].fs_block;
        let size = geometry.block_size;
        let mut payload = image[target as usize * size..(target as usize + 1) * size].to_vec();
        payload[0] = b'Q';
        let blocks = encode_v3_transaction(size, &uuid, sb.sequence, geometry.blocks_count,
            TargetWidth::Bits64, &[MetadataBlock { fs_block: target, data: &payload }]).unwrap();
        let mut encoded_journal = journal.clone();
        for (index, data) in blocks.iter().enumerate() {
            let offset = (sb.start as usize + index) * size;
            encoded_journal[offset..offset + size].copy_from_slice(data);
        }
        assert_eq!(first_transaction(&encoded_journal, &uuid, geometry.blocks_count).unwrap(), old);
        let extents = crate::reader::extent_tree(&image, &geometry, &inode).unwrap();
        for (index, data) in blocks.iter().enumerate() {
            let logical = u64::from(sb.start) + index as u64;
            let extent = extents.iter().find(|extent| !extent.unwritten && logical >= extent.logical_block
                && logical < extent.logical_block + u64::from(extent.len)).unwrap();
            let physical = extent.physical_block + logical - extent.logical_block;
            let offset = physical as usize * size;
            image[offset..offset + size].copy_from_slice(data);
        }
        fs::write(input.join("encoded-journal-v3.ext4"), image).unwrap();
    }
}
