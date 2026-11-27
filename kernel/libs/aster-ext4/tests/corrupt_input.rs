// SPDX-License-Identifier: MPL-2.0

//! Deterministic property tests over corrupted ext4 images.
//!
//! Every public parsing and recovery entry point must return an error rather
//! than panic, read out of bounds, or loop without bound when fed truncated or
//! structurally corrupted input. Each mutation is derived from a pinned
//! fixture with a fixed seed so failures are reproducible.

use std::{fs, path::PathBuf};

use aster_ext4::{analyze, jbd2, reader, recovery};

fn fixture(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.pop();
    path.push("target/qualification/inputs/ext4");
    path.push(format!("{name}.ext4"));
    fs::read(path).unwrap()
}

fn exercise(image: &[u8], journal: &[u8]) {
    let _ = analyze(image);
    if let Ok(geom) = reader::geometry(image) {
        if let Ok(root) = reader::read_inode(image, &geom, reader::ROOT_INO) {
            let _ = reader::extent_tree(image, &geom, &root);
            let _ = reader::read_file(image, &geom, &root);
            let _ = reader::read_dir(image, &geom, &root);
            let _ = reader::fast_symlink(&root);
        }
    }
    if let Ok(sb) = jbd2::parse_superblock(journal) {
        let _ = jbd2::recovery_plan(journal, &sb);
    }
    let mut copy = image.to_vec();
    let _ = recovery::mount(&mut copy, journal);
}

#[test]
fn truncations_never_panic() {
    let full = fixture("basic");
    let step = full.len() / 64;
    for length in (0..full.len()).step_by(step) {
        exercise(&full[..length], &[]);
    }
    exercise(&full, &[]);
}

#[test]
fn structural_byte_flips_never_panic() {
    let full = fixture("basic");
    let offsets = [
        1024 + 0x38,
        1024 + 0x3A,
        1024 + 0x18,
        1024 + 0x58,
        1024 + 0x5C,
        1024 + 0x60,
        1024 + 0x64,
        1024 + 0x6C,
        4096,
        4096 + 0x08,
        4096 * 34,
        4096 * 34 + 128,
    ];
    for offset in offsets {
        let mut mutated = full.clone();
        mutated[offset] ^= 0xFF;
        exercise(&mutated, &[]);
        let mut zeroed = full.clone();
        zeroed[offset] = 0;
        exercise(&zeroed, &[]);
    }
}

#[test]
fn malformed_journal_never_panic() {
    let image = fixture("basic");
    let base = vec![0u8; 4 * jbd2::JOURNAL_BLOCK_SIZE];
    for length in (0..base.len()).step_by(jbd2::JOURNAL_BLOCK_SIZE / 4) {
        exercise(&image, &base[..length]);
    }
    let mut corrupt = base.clone();
    corrupt[1024..1028].copy_from_slice(&jbd2::JBD2_MAGIC.to_be_bytes());
    corrupt[1032..1036].copy_from_slice(&1u32.to_be_bytes());
    for offset in [1036, 1040, 1044, 4096, 4096 + 12, 4096 * 3] {
        corrupt[offset] ^= 0xFF;
        exercise(&image, &corrupt);
    }
}

#[test]
fn malformed_fixture_is_refused() {
    let image = fixture("malformed");
    assert!(analyze(&image).is_err());
    exercise(&image, &[]);
}
