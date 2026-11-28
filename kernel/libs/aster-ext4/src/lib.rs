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
pub mod dir_edit;
pub mod extent_edit;
pub mod orphan;
pub mod recovery;
pub mod transaction;
pub mod xattr_edit;
pub mod write;

use reader::{BlockReader, SliceReader};

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
const SB_UUID: usize = 0x68;
const SB_DESC_SIZE: usize = 0xFE;
const SB_CHECKSUM_TYPE: usize = 0x175;
const SB_CHECKSUM_SEED: usize = 0x270;
const SB_CHECKSUM: usize = 0x3FC;
const GROUP_DESC_CHECKSUM: usize = 0x1E;

pub const STATE_CLEAN: u16 = 0x0001;
const STATE_ERROR: u16 = 0x0002;
const STATE_ORPHAN_RECOVERY: u16 = 0x0004;

const COMPAT_HAS_JOURNAL: u32 = 1 << 2;
pub const COMPAT_EXT_ATTR: u32 = 1 << 3;
pub const COMPAT_RESIZE_INODE: u32 = 1 << 4;
pub const COMPAT_DIR_INDEX: u32 = 1 << 5;
const COMPAT_ORPHAN_FILE: u32 = 1 << 12;

pub const INCOMPAT_FILETYPE: u32 = 1 << 1;
pub const INCOMPAT_RECOVERY: u32 = 1 << 2;
pub const INCOMPAT_JOURNAL_DEV: u32 = 1 << 3;
pub const INCOMPAT_META_BG: u32 = 1 << 4;
pub const INCOMPAT_EXTENTS: u32 = 1 << 6;
pub const INCOMPAT_64BIT: u32 = 1 << 7;
pub const INCOMPAT_MMP: u32 = 1 << 8;
pub const INCOMPAT_FLEX_BG: u32 = 1 << 9;
pub const INCOMPAT_CSUM_SEED: u32 = 1 << 13;

pub const RO_COMPAT_SPARSE_SUPER: u32 = 1 << 0;
pub const RO_COMPAT_LARGE_FILE: u32 = 1 << 1;
pub const RO_COMPAT_HUGE_FILE: u32 = 1 << 3;
pub const RO_COMPAT_GDT_CSUM: u32 = 1 << 4;
pub const RO_COMPAT_DIR_NLINK: u32 = 1 << 5;
pub const RO_COMPAT_EXTRA_ISIZE: u32 = 1 << 6;
pub const RO_COMPAT_METADATA_CSUM: u32 = 1 << 10;
const RO_COMPAT_ORPHAN_PRESENT: u32 = 1 << 16;

const SUPPORTED_INCOMPAT: u32 = INCOMPAT_FILETYPE
    | INCOMPAT_EXTENTS
    | INCOMPAT_64BIT
    | INCOMPAT_FLEX_BG
    | INCOMPAT_CSUM_SEED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    BadMagic,
    BadRevision,
    BadBlockSize,
    BadInodeSize,
    UnsupportedFeature(u32),
    UnsupportedWritableFeatures,
    NeedsRecovery,
    Unclean,
    FilesystemError,
    BadDescriptorSize,
    SuperblockChecksumMismatch,
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
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    pub reserved_blocks_count: u64,
    pub journal_inum: u32,
    pub features_compat: u32,
    pub features_incompat: u32,
    pub features_ro_compat: u32,
    pub group_count: usize,
    pub groups_verified: usize,
    pub metadata_checksum_seed: Option<u32>,
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

fn descriptor_size(sb: &[u8], incompat: u32, block_size: usize) -> Result<usize, Error> {
    if incompat & INCOMPAT_64BIT == 0 {
        return Ok(32);
    }
    let size = read_u16(sb, SB_DESC_SIZE)? as usize;
    if size < GROUP_DESC_SIZE_64 || size > block_size || !size.is_power_of_two() {
        return Err(Error::BadDescriptorSize);
    }
    Ok(size)
}

/// Refuses features whose semantics the reader does not implement.
pub fn check_feature_policy(info: &Info) -> Result<(), Error> {
    let unsupported = info.features_incompat & !SUPPORTED_INCOMPAT;
    if unsupported != 0 {
        return Err(Error::UnsupportedFeature(unsupported));
    }
    Ok(())
}

/// Refuses feature combinations outside the experimental writer's format subset.
pub fn check_writable_feature_policy(info: &Info) -> Result<(), Error> {
    let required_incompat = INCOMPAT_FILETYPE | INCOMPAT_EXTENTS;
    let allowed_incompat = required_incompat | INCOMPAT_FLEX_BG;
    let allowed_compat = COMPAT_HAS_JOURNAL | COMPAT_EXT_ATTR | COMPAT_RESIZE_INODE
        | COMPAT_DIR_INDEX | COMPAT_ORPHAN_FILE;
    let allowed_ro_compat = RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE | RO_COMPAT_HUGE_FILE
        | RO_COMPAT_DIR_NLINK | RO_COMPAT_EXTRA_ISIZE;
    if info.block_size != jbd2::JOURNAL_BLOCK_SIZE
        || info.features_compat & COMPAT_HAS_JOURNAL == 0
        || info.features_compat & !allowed_compat != 0
        || info.features_incompat & required_incompat != required_incompat
        || info.features_incompat & !allowed_incompat != 0
        || info.features_ro_compat & !allowed_ro_compat != 0
    {
        return Err(Error::UnsupportedWritableFeatures);
    }
    Ok(())
}

/// Parses the superblock and verifies the group descriptor table checksums.
pub fn analyze(image: &[u8]) -> Result<Info, Error> {
    analyze_from(&SliceReader::new(image))
}

/// Parses through a bounded reader so a block device need only supply the
/// superblock and group-descriptor blocks it actually needs.
pub fn analyze_from(reader: &dyn BlockReader) -> Result<Info, Error> {
    let sb = reader
        .read_at(SUPER_BLOCK_OFFSET as u64, 1024)
        .ok_or(Error::Truncated)?;
    if read_u16(&sb, SB_MAGIC)? != MAGIC {
        return Err(Error::BadMagic);
    }
    if read_u32(&sb, SB_REV_LEVEL)? < 1 {
        return Err(Error::BadRevision);
    }

    let log_block_size = read_u32(&sb, 0x18)?;
    if log_block_size > 6 {
        return Err(Error::BadBlockSize);
    }
    let block_size = MIN_BLOCK_SIZE << log_block_size;
    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) {
        return Err(Error::BadBlockSize);
    }

    let inode_size = read_u16(&sb, SB_INODE_SIZE)? as usize;
    if inode_size < 128 || inode_size > block_size || !inode_size.is_power_of_two() {
        return Err(Error::BadInodeSize);
    }

    let features_compat = read_u32(&sb, SB_FEATURE_COMPAT)?;
    let features_incompat = read_u32(&sb, SB_FEATURE_INCOMPAT)?;
    let features_ro_compat = read_u32(&sb, SB_FEATURE_RO_COMPAT)?;
    let state = read_u16(&sb, SB_STATE)?;
    if state & STATE_ERROR != 0 {
        return Err(Error::FilesystemError);
    }
    if features_incompat & INCOMPAT_RECOVERY != 0
        || state & STATE_ORPHAN_RECOVERY != 0
        || features_ro_compat & RO_COMPAT_ORPHAN_PRESENT != 0
        || read_u32(&sb, orphan::ORPHAN_HEAD_OFFSET)? != 0
    {
        return Err(Error::NeedsRecovery);
    }
    if state != STATE_CLEAN {
        return Err(Error::Unclean);
    }

    let blocks_per_group = read_u32(&sb, 0x20)? as usize;
    let blocks_count_lo = read_u32(&sb, 0x04)? as u64;
    let blocks_count_hi = if features_incompat & INCOMPAT_64BIT != 0 {
        read_u32(&sb, 0x150)? as u64
    } else {
        0
    };
    let blocks_count = blocks_count_lo | (blocks_count_hi << 32);
    let inodes_count = read_u32(&sb, 0x00)?;
    let inodes_per_group = read_u32(&sb, 0x28)? as usize;
    let free_blocks_lo = read_u32(&sb, 0x0C)? as u64;
    let reserved_blocks_lo = read_u32(&sb, 0x08)? as u64;
    let free_blocks_hi = if features_incompat & INCOMPAT_64BIT != 0 {
        read_u32(&sb, 0x158)? as u64
    } else {
        0
    };
    let reserved_blocks_hi = if features_incompat & INCOMPAT_64BIT != 0 {
        read_u32(&sb, 0x154)? as u64
    } else {
        0
    };
    let free_blocks_count = free_blocks_lo | (free_blocks_hi << 32);
    let reserved_blocks_count = reserved_blocks_lo | (reserved_blocks_hi << 32);
    let free_inodes_count = read_u32(&sb, 0x10)?;
    let journal_inum = read_u32(&sb, 0xE0)?;
    let first_data_block = u64::from(read_u32(&sb, 0x14)?);
    if blocks_per_group == 0 || inodes_per_group == 0 || blocks_count <= first_data_block {
        return Err(Error::BadBlockSize);
    }
    let group_count = (blocks_count - first_data_block).div_ceil(blocks_per_group as u64);
    let group_count = usize::try_from(group_count).map_err(|_| Error::BadBlockSize)?;
    if inodes_count.div_ceil(inodes_per_group as u32) as usize != group_count {
        return Err(Error::BadInodeSize);
    }

    let info = Info {
        block_size,
        inodes_count,
        blocks_count,
        free_blocks_count,
        free_inodes_count,
        reserved_blocks_count,
        journal_inum,
        features_compat,
        features_incompat,
        features_ro_compat,
        group_count,
        groups_verified: 0,
        metadata_checksum_seed: None,
    };
    check_feature_policy(&info)?;

    let desc_size = descriptor_size(&sb, features_incompat, block_size)?;
    let uuid = sb.get(SB_UUID..SB_UUID + 16).ok_or(Error::Truncated)?;
    let metadata_seed = if features_ro_compat & RO_COMPAT_METADATA_CSUM != 0 {
        if sb[SB_CHECKSUM_TYPE] != 1
            || ext4_crc32c(!0, &sb[..SB_CHECKSUM]) != read_u32(&sb, SB_CHECKSUM)?
        {
            return Err(Error::SuperblockChecksumMismatch);
        }
        Some(if features_incompat & INCOMPAT_CSUM_SEED != 0 {
            read_u32(&sb, SB_CHECKSUM_SEED)?
        } else {
            ext4_crc32c(!0, uuid)
        })
    } else {
        None
    };
    let table_offset = block_size * ((SUPER_BLOCK_OFFSET + 1024 + block_size - 1) / block_size);
    for index in 0..group_count {
        let desc_offset = index
            .checked_mul(desc_size)
            .ok_or(Error::GroupDescriptorTruncated(index))?;
        let start = table_offset
            .checked_add(desc_offset)
            .ok_or(Error::GroupDescriptorTruncated(index))?;
        let desc = reader
            .read_at(start as u64, desc_size)
            .ok_or(Error::GroupDescriptorTruncated(index))?;
        let index_bytes = u32::try_from(index)
            .map_err(|_| Error::BadBlockSize)?
            .to_le_bytes();
        let head = &desc[..GROUP_DESC_CHECKSUM];
        let tail = &desc[GROUP_DESC_CHECKSUM + 2..];
        let expected = read_u16(&desc, GROUP_DESC_CHECKSUM)?;
        let actual = if let Some(seed) = metadata_seed {
            let crc = ext4_crc32c(ext4_crc32c(seed, &index_bytes), head);
            ext4_crc32c(ext4_crc32c(crc, &[0, 0]), tail) as u16
        } else if features_ro_compat & RO_COMPAT_GDT_CSUM != 0 {
            let crc = crc16(crc16(crc16(!0, uuid), &index_bytes), head);
            crc16(crc, tail)
        } else {
            expected
        };
        if actual != expected {
            return Err(Error::GroupDescriptorChecksumMismatch(index));
        }
    }

    Ok(Info {
        groups_verified: group_count,
        metadata_checksum_seed: metadata_seed,
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

fn ext4_crc32c(seed: u32, bytes: &[u8]) -> u32 {
    !crc32c(!seed, bytes)
}

fn crc16(mut crc: u16, bytes: &[u8]) -> u16 {
    for byte in bytes {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xA001 } else { 0 };
        }
    }
    crc
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
        assert!(info.features_incompat & INCOMPAT_EXTENTS != 0);
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
    fn experimental_writes_refuse_unsupported_metadata_layouts() {
        assert_eq!(check_writable_feature_policy(&analyze(&fixture("basic")).unwrap()), Ok(()));
        for name in ["large-address", "multi-group"] {
            let info = analyze(&fixture(name)).unwrap();
            assert_eq!(check_writable_feature_policy(&info), Err(Error::UnsupportedWritableFeatures));
        }
    }

    #[test]
    fn large_address_fixture_has_64bit() {
        let mut image = fixture("large-address");
        let info = analyze(&image).unwrap();
        assert!(info.features_incompat & INCOMPAT_64BIT != 0);
        assert!(info.features_ro_compat & RO_COMPAT_METADATA_CSUM != 0);
        let geometry = reader::geometry(&image).unwrap();
        image[geometry.group_desc_table + GROUP_DESC_CHECKSUM] ^= 1;
        assert_eq!(analyze(&image), Err(Error::GroupDescriptorChecksumMismatch(0)));
    }

    #[test]
    fn crc32c_matches_known_vector() {
        assert_eq!(crc32c(0, b"123456789"), 0xE306_9283);
    }

    #[test]
    fn locates_internal_journal_inode() {
        let image = fixture("basic");
        let info = analyze(&image).unwrap();
        assert_eq!(info.journal_inum, 8);
        let geom = reader::geometry(&image).unwrap();
        let inode = reader::read_inode(&image, &geom, info.journal_inum).unwrap();
        assert!(!reader::extent_tree(&image, &geom, &inode).unwrap().is_empty());
    }

    #[test]
    fn refuses_malformed_fixture() {
        assert_eq!(analyze(&fixture("malformed")), Err(Error::BadMagic));
    }

    #[test]
    fn refuses_recovery_and_unsupported_features() {
        let mut image = fixture("basic");
        let superblock = &mut image[SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024];
        superblock[SB_FEATURE_INCOMPAT] |= INCOMPAT_RECOVERY as u8;
        assert_eq!(analyze(&image), Err(Error::NeedsRecovery));

        image[SUPER_BLOCK_OFFSET + SB_STATE] |= STATE_ERROR as u8;
        assert_eq!(analyze(&image), Err(Error::FilesystemError));

        let mut image = fixture("basic");
        let superblock = &mut image[SUPER_BLOCK_OFFSET..SUPER_BLOCK_OFFSET + 1024];
        let incompat = u32::from_le_bytes(
            superblock[SB_FEATURE_INCOMPAT..SB_FEATURE_INCOMPAT + 4]
                .try_into()
                .unwrap(),
        ) | INCOMPAT_MMP;
        superblock[SB_FEATURE_INCOMPAT..SB_FEATURE_INCOMPAT + 4]
            .copy_from_slice(&incompat.to_le_bytes());
        assert_eq!(analyze(&image), Err(Error::UnsupportedFeature(INCOMPAT_MMP)));
    }
}
