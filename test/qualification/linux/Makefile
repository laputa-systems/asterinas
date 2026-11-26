# SPDX-License-Identifier: MPL-2.0
#
# From the repository root, build in the pinned development container:
#   docker run --rm --privileged -v "$PWD":/root/asterinas -w /root/asterinas \
#     asterinas/dev:0.19.0-20261012 make -C test/qualification/linux
# Verify a clean rebuild with:
#   docker run --rm --privileged -v "$PWD":/root/asterinas -w /root/asterinas \
#     asterinas/dev:0.19.0-20261012 make -C test/qualification/linux clean all

SHELL := /bin/sh

EXPECTED_BZIMAGE_SHA256 := ae76287fbfee006d7171a52557b683737d13058ebecc34dc64945534ac877672

.PHONY: all verify clean

all: bzImage verify

bzImage: default.nix config ../../../distro/nixpkgs.nix ../../../flake.lock
	set -eu; \
	result=$$(nix-build --no-out-link default.nix); \
	cp -L "$$result/bzImage" bzImage.tmp; \
	mv bzImage.tmp bzImage

verify: bzImage
	set -eu; \
	sum=$$(sha256sum bzImage); \
	actual=$${sum%% *}; \
	if test "$$actual" != "$(EXPECTED_BZIMAGE_SHA256)"; then \
		printf 'bzImage sha256 mismatch: got %s expected %s\n' \
			"$$actual" "$(EXPECTED_BZIMAGE_SHA256)" >&2; \
		exit 1; \
	fi; \
	printf 'bzImage sha256 %s\n' "$$actual"

clean:
	set -eu; \
	rm -f bzImage bzImage.tmp
