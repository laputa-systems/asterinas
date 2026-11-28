// SPDX-License-Identifier: MPL-2.0

use super::Vec;

use super::{block, parse_internal_superblock, read_u32, InternalSuperblockError, JBD2_MAGIC, MAX_REVOKES, MAX_TAGS, MAX_TRANSACTION_BLOCKS};

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

/// Validates and returns the first committed transaction in an internal journal.
/// The caller must account for later transactions and revokes before replaying writes.
/// Escaped writes require restoring the JBD2 magic at the start of the payload.
///
/// # Errors
/// Returns an error for unsupported, incomplete, or corrupt journal data.
pub fn first_transaction(journal: &[u8], uuid: &[u8; 16]) -> Result<Transaction, Error> {
    let sb = parse_internal_superblock(journal, journal.len() as u64, uuid).map_err(Error::Superblock)?;
    if sb.errno != 0 || sb.start == 0 || sb.feature_incompat & 8 != 0
        || (sb.feature_compat & 1 == 0 && sb.feature_incompat & 16 == 0)
    {
        return Err(Error::Unsupported);
    }
    let size = sb.block_size as usize;
    let v3 = sb.feature_incompat & 16 != 0;
    let wide = sb.feature_incompat & 2 != 0;
    let seed = crate::ext4_crc32c(!0, uuid);
    let mut old_crc = !0;
    let mut position = sb.start;
    let mut consumed = 0usize;
    let mut writes = Vec::new();
    let mut revokes = Vec::new();
    let mut saw_record = false;
    let next = |n: u32| if n + 1 == sb.max_len { sb.first } else { n + 1 };
    loop {
        if consumed >= MAX_TRANSACTION_BLOCKS || consumed >= (sb.max_len - sb.first) as usize {
            return Err(Error::LimitExceeded);
        }
        let current = block(journal, position, size).ok_or(Error::Truncated)?;
        consumed += 1;
        if read_u32(current, 0) != Some(JBD2_MAGIC) || read_u32(current, 8) != Some(sb.sequence) {
            return Err(Error::Invalid);
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
                        if cursor + 16 > end { return Err(Error::Invalid); }
                        cursor += 16;
                    }
                    tags.push((u64::from(low) | (u64::from(high) << 32), flags, checksum));
                    if writes.len() + tags.len() > MAX_TAGS { return Err(Error::LimitExceeded); }
                    if flags & 8 != 0 { break; }
                }
                for (fs_block, flags, checksum) in tags {
                    position = next(position);
                    consumed += 1;
                    if consumed > MAX_TRANSACTION_BLOCKS || consumed >= (sb.max_len - sb.first) as usize { return Err(Error::LimitExceeded); }
                    let data = block(journal, position, size).ok_or(Error::Truncated)?;
                    if flags & 1 != 0 && data[..4] != [0; 4] { return Err(Error::Invalid); }
                    if v3 {
                        let crc = crate::ext4_crc32c(seed, &sb.sequence.to_be_bytes());
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
                writes.retain(|write| !revokes.contains(&write.fs_block));
                return Ok(Transaction { sequence: sb.sequence, writes, revokes });
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
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..3 { path.pop(); }
        path.push("target/qualification/inputs/ext4");
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
    fn genuine_committed_transactions_and_corruption() {
        for (dirty, clean, target) in [("journal-v1.ext4", "basic.ext4", 1194), ("journal-v3.ext4", "large-address.ext4", 1195)] {
            let image = fixture(dirty);
            let (mut data, uuid) = journal(&image);
            let transaction = first_transaction(&data, &uuid).unwrap();
            assert_eq!(transaction.sequence, 1);
            assert_eq!(transaction.writes, [Write { journal_block: 2, fs_block: target, escaped: false }]);
            let clean_image = fixture(clean);
            let mut expected = clean_image[target as usize * 4096..(target as usize + 1) * 4096].to_vec();
            expected[0] = b'P';
            assert_eq!(&data[8192..12288], expected);
            for offset in [4096, 4096 + 12, 8192, 12288 + 16] {
                data[offset] ^= 1;
                assert!(first_transaction(&data, &uuid).is_err(), "{dirty} offset {offset}");
                data[offset] ^= 1;
            }
            assert!(first_transaction(&data[..12288], &uuid).is_err());
        }
    }
}

#[cfg(test)]
mod edge_tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn v3() -> (Vec<u8>, [u8; 16]) {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..3 { path.pop(); }
        path.push("target/qualification/inputs/ext4/journal-v3.ext4");
        let image = fs::read(path).unwrap();
        let uuid = image[0x468..0x478].try_into().unwrap();
        let geometry = crate::reader::geometry(&image).unwrap();
        let inode = crate::reader::read_inode(&image, &geometry, 8).unwrap();
        (crate::reader::read_file(&image, &geometry, &inode).unwrap(), uuid)
    }

    fn tail(data: &mut [u8], seed: u32) {
        let offset = data.len() - 4;
        let checksum = checksum_block(seed, data, offset);
        data[offset..].copy_from_slice(&checksum.to_be_bytes());
    }

    #[test]
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
        let tx = first_transaction(&journal, &uuid).unwrap();
        assert_eq!(tx.writes, [Write { journal_block: 1, fs_block: 1195, escaped: true }]);
        journal[size] = 1;
        assert!(first_transaction(&journal, &uuid).is_err());
    }

    #[test]
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
        let tx = first_transaction(&journal, &uuid).unwrap();
        assert!(tx.writes.is_empty());
        assert_eq!(tx.revokes, [1195]);
        let revoke = &mut journal[3 * size..4 * size];
        revoke[12..16].copy_from_slice(&23u32.to_be_bytes());
        tail(revoke, seed);
        assert_eq!(first_transaction(&journal, &uuid), Err(Error::Invalid));
    }
}
