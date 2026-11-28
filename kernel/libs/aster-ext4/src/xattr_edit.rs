// SPDX-License-Identifier: MPL-2.0

//! Bounded single-block ext4 extended-attribute editing.
//!
//! One xattr block is owned by one inode. Entries store the suffix of the
//! name; the namespace prefix is carried by `name_index`. All entries are
//! rebuilt deterministically so a set or remove never leaves a partial
//! record. Names and values are length-checked before any buffer is resized.

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};

const MAGIC: u32 = 0xEA02_0000;
const HEADER_LEN: usize = 32;
const ENTRY_HEADER_LEN: usize = 16;
const MAX_ENTRIES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub name_index: u8,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrError {
    Truncated,
    BadMagic,
    NotFound,
    Exists,
    TooLarge,
    Unsupported,
    ChecksumMismatch,
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

pub fn verify_checksum(block: &[u8], physical_block: u64, seed: u32) -> Result<(), XattrError> {
    if block.len() < HEADER_LEN {
        return Err(XattrError::Truncated);
    }
    let expected = u32::from_le_bytes(block[16..20].try_into().unwrap());
    let crc = crate::ext4_crc32c(seed, &physical_block.to_le_bytes());
    let crc = crate::ext4_crc32c(crc, &block[..16]);
    let crc = crate::ext4_crc32c(crc, &[0; 4]);
    if crate::ext4_crc32c(crc, &block[20..]) != expected {
        return Err(XattrError::ChecksumMismatch);
    }
    Ok(())
}

pub fn parse(block: &[u8]) -> Result<Vec<Entry>, XattrError> {
    if block.len() < HEADER_LEN || block[..4] != MAGIC.to_le_bytes() {
        return Err(XattrError::BadMagic);
    }
    if block[8..12] != 1u32.to_le_bytes() || block[4..8] == [0; 4] {
        return Err(XattrError::Unsupported);
    }
    let mut entries = Vec::new();
    let mut cursor = HEADER_LEN;
    let mut first_value = block.len();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    loop {
        let end_marker = block.get(cursor..cursor + 4).ok_or(XattrError::Truncated)?;
        if end_marker == [0; 4] {
            if cursor + 4 > first_value {
                return Err(XattrError::Truncated);
            }
            break;
        }
        if entries.len() >= MAX_ENTRIES {
            return Err(XattrError::TooLarge);
        }
        let entry = block.get(cursor..cursor + ENTRY_HEADER_LEN).ok_or(XattrError::Truncated)?;
        let name_len = entry[0] as usize;
        let name_start = cursor + ENTRY_HEADER_LEN;
        let name = block.get(name_start..name_start + name_len).ok_or(XattrError::Truncated)?;
        if name.contains(&0) || entries.iter().any(|prior: &Entry| prior.name_index == entry[1] && prior.name == name) {
            return Err(XattrError::Truncated);
        }
        if entry[4..8] != [0; 4] {
            return Err(XattrError::Unsupported);
        }
        let value_len = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as usize;
        let value = if value_len == 0 {
            &[][..]
        } else {
            let start = u16::from_le_bytes(entry[2..4].try_into().unwrap()) as usize;
            let end = start.checked_add(value_len).ok_or(XattrError::TooLarge)?;
            if start % 4 != 0 || start < HEADER_LEN || end > block.len() {
                return Err(XattrError::Truncated);
            }
            if ranges.iter().any(|&(a, b)| start < b && a < end && (a, b) != (start, end)) {
                return Err(XattrError::Truncated);
            }
            ranges.push((start, end));
            first_value = first_value.min(start);
            &block[start..end]
        };
        entries.push(Entry {
            name_index: entry[1],
            name: name.to_vec(),
            value: value.to_vec(),
        });
        cursor = name_start + align4(name_len);
        if cursor > first_value {
            return Err(XattrError::Truncated);
        }
    }
    Ok(entries)
}

fn build(entries: &mut [Entry], block_size: usize) -> Result<Vec<u8>, XattrError> {
    if !(HEADER_LEN + 4..=1 << 16).contains(&block_size) || entries.len() > MAX_ENTRIES {
        return Err(XattrError::TooLarge);
    }
    entries.sort_unstable_by(|a, b| {
        (a.name_index, a.name.len(), &a.name).cmp(&(b.name_index, b.name.len(), &b.name))
    });
    let mut block = vec![0u8; block_size];
    block[..4].copy_from_slice(&MAGIC.to_le_bytes());
    block[4..8].copy_from_slice(&1u32.to_le_bytes());
    block[8..12].copy_from_slice(&1u32.to_le_bytes());
    let mut cursor = HEADER_LEN;
    let mut values = block_size;
    let mut block_hash = 0u32;
    let mut has_unhashed_entry = false;
    for entry in entries {
        if entry.name.len() > 255 || entry.value.len() > u16::MAX as usize {
            return Err(XattrError::TooLarge);
        }
        let name_padded = align4(entry.name.len());
        let value_padded = align4(entry.value.len());
        let entry_len = ENTRY_HEADER_LEN + name_padded;
        values = values.checked_sub(value_padded).ok_or(XattrError::TooLarge)?;
        if cursor + entry_len + 4 > values {
            return Err(XattrError::TooLarge);
        }
        let mut hash = entry.name.iter().fold(0u32, |hash, byte| hash.rotate_left(5) ^ u32::from(*byte));
        let header = &mut block[cursor..cursor + ENTRY_HEADER_LEN];
        header[0] = entry.name.len() as u8;
        header[1] = entry.name_index;
        header[8..12].copy_from_slice(&(entry.value.len() as u32).to_le_bytes());
        if !entry.value.is_empty() {
            header[2..4].copy_from_slice(&(values as u16).to_le_bytes());
            block[values..values + entry.value.len()].copy_from_slice(&entry.value);
            for word in block[values..values + value_padded].chunks_exact(4) {
                hash = hash.rotate_left(16) ^ u32::from_le_bytes(word.try_into().unwrap());
            }
        }
        block[cursor + 12..cursor + 16].copy_from_slice(&hash.to_le_bytes());
        let name_start = cursor + ENTRY_HEADER_LEN;
        block[name_start..name_start + entry.name.len()].copy_from_slice(&entry.name);
        cursor += entry_len;
        block_hash = block_hash.rotate_left(16) ^ hash;
        has_unhashed_entry |= hash == 0;
    }
    if !has_unhashed_entry {
        block[12..16].copy_from_slice(&block_hash.to_le_bytes());
    }
    Ok(block)
}

fn matches(entry: &Entry, name_index: u8, name: &[u8]) -> bool {
    entry.name_index == name_index && entry.name == name
}

pub fn set(
    block: &[u8],
    name_index: u8,
    name: &[u8],
    value: &[u8],
    block_size: usize,
    replace_only: bool,
    create_only: bool,
) -> Result<Vec<u8>, XattrError> {
    let mut entries = if block.is_empty() {
        Vec::new()
    } else {
        editable_entries(block)?
    };
    let position = entries
        .iter()
        .position(|entry| matches(entry, name_index, name));
    match (position, replace_only, create_only) {
        (None, true, _) => return Err(XattrError::NotFound),
        (Some(_), _, true) => return Err(XattrError::Exists),
        _ => {}
    }
    let entry = Entry {
        name_index,
        name: name.to_vec(),
        value: value.to_vec(),
    };
    if let Some(index) = position {
        entries[index] = entry;
    } else {
        entries.push(entry);
    }
    build(&mut entries, block_size)
}

pub fn remove(block: &[u8], name_index: u8, name: &[u8], block_size: usize) -> Result<Vec<u8>, XattrError> {
    let mut entries = editable_entries(block)?;
    let position = entries
        .iter()
        .position(|entry| matches(entry, name_index, name))
        .ok_or(XattrError::NotFound)?;
    entries.remove(position);
    build(&mut entries, block_size)
}

fn editable_entries(block: &[u8]) -> Result<Vec<Entry>, XattrError> {
    let entries = parse(block)?;
    if block[4..8] != 1u32.to_le_bytes() || block[16..20] != [0; 4] {
        return Err(XattrError::Unsupported);
    }
    Ok(entries)
}

pub fn get(block: &[u8], name_index: u8, name: &[u8]) -> Result<Option<Vec<u8>>, XattrError> {
    Ok(parse(block)?
        .into_iter()
        .find(|entry| matches(entry, name_index, name))
        .map(|entry| entry.value))
}

pub fn names(block: &[u8]) -> Result<Vec<(u8, String)>, XattrError> {
    parse(block)?
        .into_iter()
        .map(|entry| {
            Ok((
                entry.name_index,
                String::from_utf8(entry.name).map_err(|_| XattrError::Truncated)?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    fn e2fsprogs_external_attributes(seed: &str) -> (Vec<u8>, core::ops::Range<usize>) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../target/qualification/inputs/ext4")
            .join(format!("{seed}-external-xattrs.ext4"));
        let image = fs::read(path).unwrap();
        let geom = crate::reader::geometry(&image).unwrap();
        let root = crate::reader::read_inode(&image, &geom, crate::reader::ROOT_INO).unwrap();
        let ino = crate::reader::lookup(&image, &geom, &root, b"marker.txt").unwrap();
        let offset = crate::reader::inode_offset_from(&crate::reader::SliceReader::new(&image), &geom, ino).unwrap() as usize;
        let block = u32::from_le_bytes(image[offset + 0x68..offset + 0x6C].try_into().unwrap()) as usize;
        let start = block * geom.block_size;
        (image, start..start + geom.block_size)
    }

    #[test]
    #[ignore = "requires external-xattrs.ext4 from fixtures/ext4/build-xattrs.sh"]
    fn reads_e2fsprogs_external_attributes() {
        let (image, range) = e2fsprogs_external_attributes("basic");
        let data = &image[range];
        assert_eq!(get(data, 1, b"foo"), Ok(Some(b"bar".to_vec())));
        assert_eq!(get(data, 4, b"author"), Ok(Some(b"asterinas".to_vec())));
    }

    #[test]
    #[ignore = "requires the checksummed fixture from fixtures/ext4/build-xattrs.sh"]
    fn verifies_e2fsprogs_attribute_checksum() {
        let (mut image, range) = e2fsprogs_external_attributes("large-address");
        let seed = crate::analyze(&image).unwrap().metadata_checksum_seed.unwrap();
        let block = (range.start / range.len()) as u64;
        assert_eq!(verify_checksum(&image[range.clone()], block, seed), Ok(()));
        image[range.start + 16] ^= 1;
        assert_eq!(verify_checksum(&image[range], block, seed), Err(XattrError::ChecksumMismatch));
    }

    #[test]
    #[ignore = "produces a clone for pinned e2fsprogs validation"]
    fn writes_external_attributes_for_e2fsprogs() {
        let (mut image, range) = e2fsprogs_external_attributes("basic");
        let modified = set(&image[range.clone()], 1, b"foo", b"candidate-value", range.len(), true, false).unwrap();
        image[range].copy_from_slice(&modified);
        let output = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../target/qualification/inputs/ext4/candidate-xattrs.ext4");
        fs::write(output, image).unwrap();
    }

    #[test]
    fn set_get_list_replace_and_remove() {
        let block_size = 4096usize;
        let mut block = set(&[], 1, b"foo", b"bar", block_size, false, false).unwrap();
        assert_eq!(get(&block, 1, b"foo"), Ok(Some(b"bar".to_vec())));
        assert_eq!(names(&block).unwrap().len(), 1);
        assert_eq!(set(&block, 1, b"foo", b"baz", block_size, true, false).unwrap(),
                   set(&block, 1, b"foo", b"baz", block_size, false, false).unwrap());
        assert_eq!(get(&set(&block, 1, b"foo", b"baz", block_size, true, false).unwrap(), 1, b"foo"),
                   Ok(Some(b"baz".to_vec())));
        assert_eq!(set(&block, 1, b"foo", b"x", block_size, false, true), Err(XattrError::Exists));
        assert_eq!(set(&block, 1, b"other", b"x", block_size, true, false), Err(XattrError::NotFound));
        block = remove(&block, 1, b"foo", block_size).unwrap();
        assert_eq!(get(&block, 1, b"foo"), Ok(None));
        assert_eq!(remove(&block, 1, b"foo", block_size), Err(XattrError::NotFound));
    }

    #[test]
    fn rejects_bad_magic_and_oversize() {
        let block_size = 4096usize;
        let mut block = set(&[], 1, b"a", b"b", block_size, false, false).unwrap();
        block[3] = 0;
        assert_eq!(get(&block, 1, b"a"), Err(XattrError::BadMagic));
        let huge = vec![0u8; 70000];
        assert_eq!(set(&[], 1, b"a", &huge, block_size, false, false), Err(XattrError::TooLarge));
    }

    #[test]
    fn refuses_values_overlapping_the_entries() {
        let mut block = set(&[], 1, b"foo", b"bar", 4096, false, false).unwrap();
        assert_eq!(u32::from_le_bytes(block[8..12].try_into().unwrap()), 1);
        assert_eq!(&block[48..51], b"foo");
        block[34..36].copy_from_slice(&48u16.to_le_bytes());
        assert_eq!(parse(&block), Err(XattrError::Truncated));
    }

    #[test]
    fn refuses_ambiguous_entries_and_partially_overlapping_values() {
        let original = set(&[], 1, b"aaa", b"value1", 4096, false, false).unwrap();
        let original = set(&original, 1, b"bbb", b"value2", 4096, false, false).unwrap();
        let mut duplicate = original.clone();
        duplicate[68..71].copy_from_slice(b"aaa");
        assert_eq!(parse(&duplicate), Err(XattrError::Truncated));

        let mut overlap = original;
        overlap[54..56].copy_from_slice(&4084u16.to_le_bytes());
        assert_eq!(parse(&overlap), Err(XattrError::Truncated));
    }
}
