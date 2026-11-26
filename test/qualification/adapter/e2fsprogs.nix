# SPDX-License-Identifier: MPL-2.0

let
  pkgs = import ../../../distro/nixpkgs.nix { };
in
pkgs.e2fsprogs
