# SPDX-License-Identifier: MPL-2.0

let
  pkgs = import ../../../distro/nixpkgs.nix { };
  static = pkgs.pkgsCross.gnu64.pkgsStatic;
in
static.stdenv.mkDerivation {
  pname = "asterinas-qualification-probe";
  version = "lc06-r1";
  src = ./.;

  nativeBuildInputs = [ static.stdenv.cc ];

  dontConfigure = true;
  dontFixup = true;

  buildPhase = ''
    runHook preBuild
    "$CC" -O2 -static -Wall -Wextra -Werror -o probe probe.c
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -D -m 0755 probe $out/init
    runHook postInstall
  '';
}
