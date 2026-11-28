// SPDX-License-Identifier: MPL-2.0

//! Bounded linear directory-entry editing for LC-20/21.
//!
//! Directory blocks are parsed into entries and rebuilt deterministically, so
//! adding or removing an entry never leaves a partially written record. Every
//! record length and name length is validated before use.

extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirError {
    Truncated,
    NameTooLong,
    NotFound,
    Exists,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawDirEntry {
    pub ino: u32,
    pub name: Vec<u8>,
    pub file_type: u8,
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

pub fn parse(data: &[u8]) -> Result<Vec<RawDirEntry>, DirError> {
    if data.iter().all(|byte| *byte == 0) {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let mut cursor = 0usize;
    while cursor + 8 <= data.len() {
        let ino = u32::from_le_bytes(
            data[cursor..cursor + 4]
                .try_into()
                .map_err(|_| DirError::Truncated)?,
        );
        let rec_len = u16::from_le_bytes(
            data[cursor + 4..cursor + 6]
                .try_into()
                .map_err(|_| DirError::Truncated)?,
        ) as usize;
        let name_len = data[cursor + 6] as usize;
        let file_type = data[cursor + 7];
        if rec_len < 8 || cursor + rec_len > data.len() || name_len + 8 > rec_len {
            return Err(DirError::Truncated);
        }
        if ino != 0 {
            entries.push(RawDirEntry {
                ino,
                name: data[cursor + 8..cursor + 8 + name_len].to_vec(),
                file_type,
            });
        }
        cursor += rec_len;
    }
    Ok(entries)
}

fn build(entries: &[RawDirEntry], block_size: usize) -> Result<Vec<u8>, DirError> {
    let mut data = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.name.len() > 255 {
            return Err(DirError::NameTooLong);
        }
        let used = align4(8 + entry.name.len());
        let rec_len = if index + 1 == entries.len() {
            block_size.saturating_sub(data.len()).max(used)
        } else {
            used
        };
        if rec_len < used {
            return Err(DirError::Truncated);
        }
        let start = data.len();
        data.extend_from_slice(&entry.ino.to_le_bytes());
        data.extend_from_slice(&(rec_len as u16).to_le_bytes());
        data.push(entry.name.len() as u8);
        data.push(entry.file_type);
        data.extend_from_slice(&entry.name);
        data.resize(start + rec_len, 0);
    }
    Ok(data)
}

pub fn add(
    data: &[u8],
    ino: u32,
    name: &[u8],
    file_type: u8,
    block_size: usize,
) -> Result<Vec<u8>, DirError> {
    let mut entries = parse(data)?;
    if entries
        .iter()
        .any(|entry| entry.name == name || entry.ino == ino)
    {
        return Err(DirError::Exists);
    }
    entries.push(RawDirEntry {
        ino,
        name: name.to_vec(),
        file_type,
    });
    build(&entries, block_size)
}

pub fn remove(data: &[u8], name: &[u8], block_size: usize) -> Result<Vec<u8>, DirError> {
    let mut entries = parse(data)?;
    let before = entries.len();
    entries.retain(|entry| entry.name != name);
    if entries.len() == before {
        return Err(DirError::NotFound);
    }
    build(&entries, block_size)
}

/// Changes the name of the entry with `ino`, preserving its file type.
pub fn rename_entry(
    data: &[u8],
    ino: u32,
    new_name: &[u8],
    block_size: usize,
) -> Result<Vec<u8>, DirError> {
    let mut entries = parse(data)?;
    if entries.iter().any(|entry| entry.name == new_name) {
        return Err(DirError::Exists);
    }
    let entry = entries
        .iter_mut()
        .find(|entry| entry.ino == ino)
        .ok_or(DirError::NotFound)?;
    entry.name = new_name.to_vec();
    build(&entries, block_size)
}

/// True when only the dot entries remain (an empty directory).
pub fn is_empty(data: &[u8]) -> Result<bool, DirError> {
    Ok(parse(data)?
        .iter()
        .all(|entry| entry.name == b"." || entry.name == b".."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_remove_round_trip() {
        let block = 4096usize;
        let mut data = vec![0u8; block];
        data = add(&data, 2, b".", 2, block).unwrap();
        data = add(&data, 3, b"..", 2, block).unwrap();
        data = add(&data, 11, b"marker.txt", 1, block).unwrap();
        let entries = parse(&data).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].name, b"marker.txt");
        data = remove(&data, b"marker.txt", block).unwrap();
        assert_eq!(parse(&data).unwrap().len(), 2);
    }

    #[test]
    fn rename_and_empty_detection() {
        let block = 4096usize;
        let mut data = add(&vec![0u8; block], 2, b".", 2, block).unwrap();
        data = add(&data, 3, b"..", 2, block).unwrap();
        assert!(is_empty(&data).unwrap());
        data = add(&data, 11, b"a", 1, block).unwrap();
        assert!(!is_empty(&data).unwrap());
        data = rename_entry(&data, 11, b"b", block).unwrap();
        let entries = parse(&data).unwrap();
        assert_eq!(entries[2].name, b"b");
        data = remove(&data, b"b", block).unwrap();
        assert!(is_empty(&data).unwrap());
    }

    #[test]
    fn rejects_duplicate_and_bad_records() {
        let block = 4096usize;
        let mut data = add(&vec![0u8; block], 11, b"a", 1, block).unwrap();
        assert_eq!(add(&data, 12, b"a", 1, block), Err(DirError::Exists));
        data[4] = 1;
        assert_eq!(parse(&data), Err(DirError::Truncated));
    }
}
