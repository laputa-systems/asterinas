#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
set -eu

tools=$(nix-build --no-out-link test/qualification/adapter/e2fsprogs.nix)
directory=target/qualification/inputs/ext4
mkdir -p .work/tmp
scratch=$(mktemp -d .work/tmp/ext4-xattrs.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export E2FSPROGS_FAKE_TIME=0 SOURCE_DATE_EPOCH=0

printf 'ea_set /marker.txt user.foo bar\nea_set /marker.txt trusted.author asterinas\n' > "$scratch/commands"
for seed in basic large-address; do
    cp "$directory/$seed.ext4" "$scratch/xattrs.ext4"
    "$tools/bin/debugfs" -w -f "$scratch/commands" "$scratch/xattrs.ext4"
    "$tools/bin/debugfs" -R "ea_get -f $scratch/value /marker.txt user.foo" "$scratch/xattrs.ext4"
    test "$(cat "$scratch/value")" = bar
    "$tools/bin/e2fsck" -fn "$scratch/xattrs.ext4"
    mv "$scratch/xattrs.ext4" "$directory/$seed-external-xattrs.ext4"
done
