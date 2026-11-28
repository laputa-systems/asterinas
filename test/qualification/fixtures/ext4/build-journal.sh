#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

tools=$(nix-build --no-out-link test/qualification/adapter/e2fsprogs.nix)
directory=target/qualification/inputs/ext4
mkdir -p .work/tmp
scratch=$(mktemp -d .work/tmp/ext4-journal.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export E2FSPROGS_FAKE_TIME=0 SOURCE_DATE_EPOCH=0

for profile in v1 v3 v3-stream; do
    if [ "$profile" = v1 ]; then
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
    {
        printf 'journal_open -c -v 3\njournal_write -b %s %s/payload\n' "$data_block" "$scratch"
        if [ "$profile" = v3-stream ]; then
            cp "$scratch/payload" "$scratch/next-payload"
            printf R | dd of="$scratch/next-payload" conv=notrunc status=none
            printf 'journal_write -b %s %s/next-payload\n' "$data_block" "$scratch"
            marker=Rc14-large-address
        fi
        printf 'journal_close\n'
    } > "$scratch/commands"
    "$tools/bin/debugfs" -w -f "$scratch/commands" "$scratch/dirty.ext4"
    "$tools/bin/debugfs" -R 'logdump -aS' "$scratch/dirty.ext4"
    test "$("$tools/bin/debugfs" -R 'cat /marker.txt' "$scratch/dirty.ext4")" != "$marker"
    cp "$scratch/dirty.ext4" "$scratch/reference.ext4"
    "$tools/bin/e2fsck" -p -E journal_only "$scratch/reference.ext4"
    "$tools/bin/e2fsck" -fn "$scratch/reference.ext4"
    test "$("$tools/bin/debugfs" -R 'cat /marker.txt' "$scratch/reference.ext4")" = "$marker"
    mv "$scratch/dirty.ext4" "$directory/journal-$profile.ext4"
    sha256sum "$directory/journal-$profile.ext4"
done

cargo test -p aster-ext4 jbd2::internal::encoder_tests::emit_v3_fixture_for_independent_replay -- --exact --ignored
encoded="$directory/encoded-journal-v3.ext4"
sha256sum "$encoded"
cp "$encoded" "$scratch/encoder-recovery.ext4"
"$tools/bin/e2fsck" -p -E journal_only "$scratch/encoder-recovery.ext4"
cp "$scratch/encoder-recovery.ext4" "$scratch/encoder-check.ext4"
"$tools/bin/e2fsck" -fn "$scratch/encoder-check.ext4"
test "$("$tools/bin/debugfs" -R 'cat /marker.txt' "$scratch/encoder-recovery.ext4")" = Qc14-large-address
