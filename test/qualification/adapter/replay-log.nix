# SPDX-License-Identifier: MPL-2.0

let
  pkgs = import ../../../distro/nixpkgs.nix { };
  logWrites = "${pkgs.xfstests.src}/src/log-writes";
in
pkgs.runCommandCC "qualification-replay-log" { } ''
  mkdir -p "$out/bin"
  cc -std=gnu11 -O2 ${logWrites}/replay-log.c ${logWrites}/log-writes.c -o "$out/bin/replay-log"
''
