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
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

pub fn new_block() -> Vec<u8> {
    let mut block = vec![0u8; HEADER_LEN];
    block[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    block[4..8].copy_from_slice(&1u32.to_le_bytes());
    block
}

pub fn parse(block: &[u8]) -> Result<Vec<Entry>, XattrError> {
    if block.len() < HEADER_LEN || u32::from_le_bytes(block[0..4].try_into().unwrap()) != MAGIC {
        return Err(XattrError::BadMagic);
    }
    let mut entries = Vec::new();
    let mut cursor = HEADER_LEN;
    while cursor < block.len() {
        if entries.len() >= MAX_ENTRIES {
            return Err(XattrError::TooLarge);
        }
        if cursor + 8 > block.len() {
            return Err(XattrError::Truncated);
        }
        if block[cursor..cursor + 8].iter().all(|byte| *byte == 0) {
            break;
        }
        let name_len = block[cursor] as usize;
        let name_index = block[cursor + 1];
        let value_len = u16::from_le_bytes(block[cursor + 2..cursor + 4].try_into().unwrap()) as usize;
        let name_start = cursor + 8;
        let value_start = name_start + align4(name_len);
        let end = value_start + align4(value_len);
        if end > block.len() {
            return Err(XattrError::Truncated);
        }
        entries.push(Entry {
            name_index,
            name: block[name_start..name_start + name_len].to_vec(),
            value: block[value_start..value_start + value_len].to_vec(),
        });
        cursor = end;
    }
    Ok(entries)
}

fn build(entries: &[Entry], block_size: usize) -> Result<Vec<u8>, XattrError> {
    let mut block = new_block();
    for entry in entries {
        if entry.name.len() > 255 || entry.value.len() > u16::MAX as usize {
            return Err(XattrError::TooLarge);
        }
        let name_padded = align4(entry.name.len());
        let value_padded = align4(entry.value.len());
        let entry_len = 8 + name_padded + value_padded;
        if block.len() + entry_len > block_size {
            return Err(XattrError::TooLarge);
        }
        let start = block.len();
        block.push(entry.name.len() as u8);
        block.push(entry.name_index);
        block.extend_from_slice(&(entry.value.len() as u16).to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes());
        block.extend_from_slice(&entry.name);
        block.resize(start + 8 + name_padded, 0);
        block.extend_from_slice(&entry.value);
        block.resize(start + entry_len, 0);
    }
    block.resize(block_size, 0);
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
        parse(block)?
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
    build(&entries, block_size)
}

pub fn remove(block: &[u8], name_index: u8, name: &[u8], block_size: usize) -> Result<Vec<u8>, XattrError> {
    let mut entries = parse(block)?;
    let position = entries
        .iter()
        .position(|entry| matches(entry, name_index, name))
        .ok_or(XattrError::NotFound)?;
    entries.remove(position);
    build(&entries, block_size)
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
}
