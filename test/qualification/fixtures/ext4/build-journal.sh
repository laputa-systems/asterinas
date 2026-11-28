#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

tools=$(nix-build --no-out-link test/qualification/adapter/e2fsprogs.nix)
directory=target/qualification/inputs/ext4
mkdir -p .work/tmp
scratch=$(mktemp -d .work/tmp/ext4-journal.XXXXXX)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
export E2FSPROGS_FAKE_TIME=0 SOURCE_DATE_EPOCH=0

for version in 1 3; do
    if [ "$version" -eq 1 ]; then
        fixture="$directory/basic.ext4"
        marker=Pc14-basic
    else
        fixture="$directory/large-address.ext4"
        marker=Pc14-large-address
    fi
    "$tools/bin/e2fsck" -fn "$fixture"
    data_block=$("$tools/bin/debugfs" -R 'bmap /marker.txt 0' "$fixture")
    test "$data_block" -gt 0
    dd if="$fixture" of="$scratch/payload" bs=4096 skip="$data_block" count=1 status=none
    printf P | dd of="$scratch/payload" conv=notrunc status=none
    cp "$fixture" "$scratch/dirty.ext4"
    printf 'journal_open -c -v 3\njournal_write -b %s %s/payload\njournal_close\n' \
        "$data_block" "$scratch" > "$scratch/commands"
    "$tools/bin/debugfs" -w -f "$scratch/commands" "$scratch/dirty.ext4"
    "$tools/bin/debugfs" -R 'logdump -aS' "$scratch/dirty.ext4"
    test "$("$tools/bin/debugfs" -R 'cat /marker.txt' "$scratch/dirty.ext4")" != "$marker"
    cp "$scratch/dirty.ext4" "$scratch/reference.ext4"
    "$tools/bin/e2fsck" -p -E journal_only "$scratch/reference.ext4"
    "$tools/bin/e2fsck" -fn "$scratch/reference.ext4"
    test "$("$tools/bin/debugfs" -R 'cat /marker.txt' "$scratch/reference.ext4")" = "$marker"
    mv "$scratch/dirty.ext4" "$directory/journal-v$version.ext4"
    sha256sum "$directory/journal-v$version.ext4"
done
