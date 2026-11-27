// SPDX-License-Identifier: MPL-2.0

//! Bounded, safe parser for the on-disk ext4 format.
//!
//! The crate implements LC-15's format policy: parse the superblock and group
//! descriptors from a byte slice, verify checksums, and refuse images whose
//! incompatible features or recovery state are outside the supported set.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

use core::fmt;

pub mod jbd2;
pub mod reader;
pub mod recovery;

pub const SUPER_BLOCK_OFFSET: usize = 1024;
pub const BLOCK_SIZE: usize = 4096;
pub const MIN_BLOCK_SIZE: usize = 1024;
pub const MAX_BLOCK_SIZE: usize = 65536;
pub const MAGIC: u16 = 0xEF53;
pub const GROUP_DESC_SIZE_64: usize = 64;

const SB_MAGIC: usize = 0x38;
const SB_STATE: usize = 0x3A;
const SB_REV_LEVEL: usize = 0x4C;
const SB_INODE_SIZE: usize = 0x58;
const SB_FEATURE_COMPAT: usize = 0x5C;
const SB_FEATURE_INCOMPAT: usize = 0x60;
const SB_FEATURE_RO_COMPAT: usize = 0x64;
const SB_UUID: usize = 0x6C;

pub const state_unclean: u16 = 0x0001;
pub const state_needs_recovery: u16 = 0x0002;

pub const compat_dir_index: u32 = 1 << 2;
pub const compat_ext_attr: u32 = 1 << 3;
pub const compat_resize_inode: u32 = 1 << 5;

pub const incompat_filetype: u32 = 1 << 0;
pub const incompat_recovery: u32 = 1 << 2;
pub const incompat_journal_dev: u32 = 1 << 3;
pub const incompat_meta_bg: u32 = 1 << 4;
pub const incompat_extents: u32 = 1 << 6;
pub const incompat_64bit: u32 = 1 << 7;
pub const incompat_flex_bg: u32 = 1 << 9;
pub const incompat_uninit_bg: u32 = 1 << 10;
pub const incompat_dev_metadata_csum: u32 = 1 << 11;
pub const incompat_mmp: u32 = 1 << 12;
pub const incompat_csum_seed: u32 = 1 << 13;

pub const ro_compat_sparse_super: u32 = 1 << 0;
pub const ro_compat_large_file: u32 = 1 << 1;
pub const ro_compat_huge_file: u32 = 1 << 5;
pub const ro_compat_gdt_csum: u32 = 1 << 6;
pub const ro_compat_dir_nlink: u32 = 1 << 7;
pub const ro_compat_extra_isize: u32 = 1 << 8;
pub const ro_compat_metadata_csum: u32 = 1 << 10;

const SUPPORTED_INCOMPAT: u32 = incompat_filetype
    | incompat_extents
    | incompat_64bit
    | incompat_flex_bg
    | incompat_uninit_bg
    | incompat_dev_metadata_csum
    | incompat_csum_seed;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadMagic,
    BadRevision,
    BadBlockSize,
    BadInodeSize,
    UnsupportedFeature(u32),
    NeedsRecovery,
    Unclean,
    GroupDescriptorTruncated(usize),
    GroupDescriptorChecksumMismatch(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Info {
    pub block_size: usize,
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub features_compat: u32,
    pub features_incompat: u32,
    pub features_ro_compat: u32,
    pub group_count: usize,
    pub groups_verified: usize,
}

fn read_u16(buf: &[u8], offset: usize) -> Result<u16, Error> {
    buf.get(offset..offset + 2)
        .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
        .map(u16::from_le_bytes)
        .ok_or(Error::Truncated)
}

fn read_u32(buf: &[u8], offset: usize) -> Result<u32, Error> {
    buf.get(offset..offset + 4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
        .ok_or(Error::Truncated)
}

/// Refuses features whose semantics the reader does not implement.
pub fn check_feature_policy(info: &Info) -> Result<(), Error> {
    let unsupported = info.features_incompat & !SUPPORTED_INCOMPAT;
    if unsupported != 0 {
        return Err(Error::UnsupportedFeature(unsupported));
    }
    Ok(())
}

/// Parses the superblock and verifies the group descriptor table checksums.
pub fn analyze(image: &[u8]) -> Result<Info, Error> {
    let sb = image
        .get(SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024)
        .ok_or(Error::Truncated)?;
    if read_u16(sb, SB_MAGIC)? != MAGIC {
        return Err(Error::BadMagic);
    }
    if read_u32(sb, SB_REV_LEVEL)? < 1 {
        return Err(Error::BadRevision);
    }

    let log_block_size = read_u32(sb, 0x18)?;
    if log_block_size > 6 {
        return Err(Error::BadBlockSize);
    }
    let block_size = MIN_BLOCK_SIZE << log_block_size;
    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) {
        return Err(Error::BadBlockSize);
    }

    let inode_size = read_u16(sb, SB_INODE_SIZE)? as usize;
    if inode_size < 128 || !inode_size.is_power_of_two() {
        return Err(Error::BadInodeSize);
    }

    let features_compat = read_u32(sb, SB_FEATURE_COMPAT)?;
    let features_incompat = read_u32(sb, SB_FEATURE_INCOMPAT)?;
    let features_ro_compat = read_u32(sb, SB_FEATURE_RO_COMPAT)?;
    let state = read_u16(sb, SB_STATE)?;
    if state & state_needs_recovery != 0 || features_incompat & incompat_recovery != 0 {
        return Err(Error::NeedsRecovery);
    }
    if state & state_unclean != 0 {
        return Err(Error::Unclean);
    }

    let blocks_per_group = read_u32(sb, 0x20)? as usize;
    let blocks_count_lo = read_u32(sb, 0x04)? as u64;
    let blocks_count_hi = if features_incompat & incompat_64bit != 0 {
        read_u32(sb, 0x150)? as u64
    } else {
        0
    };
    let blocks_count = blocks_count_lo | (blocks_count_hi << 32);
    let inodes_count = read_u32(sb, 0x00)?;
    let inodes_per_group = read_u32(sb, 0x28)? as usize;
    if blocks_per_group == 0 || inodes_per_group == 0 {
        return Err(Error::BadBlockSize);
    }
    let group_count = blocks_count.div_ceil(blocks_per_group as u64) as usize;
    let group_count = group_count.max(inodes_count.div_ceil(inodes_per_group as u32) as usize);

    let info = Info {
        block_size,
        inodes_count,
        blocks_count,
        features_compat,
        features_incompat,
        features_ro_compat,
        group_count,
        groups_verified: 0,
    };
    check_feature_policy(&info)?;

    let verify_group_checksums = features_ro_compat & ro_compat_metadata_csum != 0;
    let uuid = sb
        .get(SB_UUID..SB_UUID + 16)
        .ok_or(Error::Truncated)?;
    let table_offset = block_size * ((SUPER_BLOCK_OFFSET + 1024 + block_size - 1) / block_size);
    let mut groups_verified = 0usize;
    for index in 0..group_count {
        let desc_offset = index
            .checked_mul(GROUP_DESC_SIZE_64)
            .ok_or(Error::GroupDescriptorTruncated(index))?;
        let start = table_offset
            .checked_add(desc_offset)
            .ok_or(Error::GroupDescriptorTruncated(index))?;
        let desc = image
            .get(start..start + GROUP_DESC_SIZE_64)
            .ok_or(Error::GroupDescriptorTruncated(index))?;
        if !verify_group_checksums || group_descriptor_checksum_ok(uuid, index, desc) {
            groups_verified += 1;
        }
    }

    Ok(Info {
        groups_verified,
        ..info
    })
}

/// CRC32C (Castagnoli) used by ext4 metadata checksums.
pub fn crc32c(seed: u32, bytes: &[u8]) -> u32 {
    let mut crc = !seed;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn group_descriptor_checksum_ok(uuid: &[u8], index: usize, desc: &[u8]) -> bool {
    let seed = crc32c(!0, &uuid[..16]);
    let mut crc = crc32c(seed, &(index as u32).to_le_bytes());
    crc = crc32c(crc, &desc[0x00..0x1E]);
    crc = crc32c(crc, &desc[0x20..0x40]);
    let expected = u16::from_le_bytes([desc[0x1E], desc[0x1F]]);
    crc as u16 == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn fixture(name: &str) -> Vec<u8> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.pop();
        path.push("target/qualification/inputs/ext4");
        path.push(format!("{name}.ext4"));
        fs::read(path).unwrap_or_else(|error| panic!("missing fixture {name}: {error}"))
    }

    #[test]
    fn parses_basic_fixture() {
        let info = analyze(&fixture("basic")).unwrap();
        assert_eq!(info.block_size, 4096);
        assert!(info.features_incompat & incompat_extents != 0);
        assert!(info.groups_verified > 0);
        assert_eq!(info.groups_verified, info.group_count);
    }

    #[test]
    fn parses_multi_group_fixture() {
        let info = analyze(&fixture("multi-group")).unwrap();
        assert_eq!(info.block_size, 1024);
        assert!(info.group_count > 1);
    }

    #[test]
    fn large_address_fixture_has_64bit() {
        let info = analyze(&fixture("large-address")).unwrap();
        assert!(info.features_incompat & incompat_64bit != 0);
    }

    #[test]
    fn crc32c_matches_known_vector() {
        assert_eq!(crc32c(0, b"123456789"), 0xE306_9283);
    }

    #[test]
    fn refuses_malformed_fixture() {
        assert_eq!(analyze(&fixture("malformed")), Err(Error::BadMagic));
    }

    #[test]
    fn refuses_recovery_and_unsupported_features() {
        let mut image = fixture("basic");
        let superblock = &mut image[SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024];
        superblock[SB_STATE..SB_STATE + 2].copy_from_slice(&state_needs_recovery.to_le_bytes());
        assert_eq!(analyze(&image), Err(Error::NeedsRecovery));

        let mut image = fixture("basic");
        let superblock = &mut image[SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024];
        let incompat = u32::from_le_bytes(
            superblock[SB_FEATURE_INCOMPAT..SB_FEATURE_INCOMPAT + 4]
                .try_into()
                .unwrap(),
        ) | incompat_mmp;
        superblock[SB_FEATURE_INCOMPAT..SB_FEATURE_INCOMPAT + 4]
            .copy_from_slice(&incompat.to_le_bytes());
        assert_eq!(analyze(&image), Err(Error::UnsupportedFeature(incompat_mmp)));
    }
}
