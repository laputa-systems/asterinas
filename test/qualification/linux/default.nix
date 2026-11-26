# SPDX-License-Identifier: MPL-2.0

let
  version = "6.18.65";
  pkgs = import ../../../distro/nixpkgs.nix { };
  cross = pkgs.pkgsCross.gnu64;
in
cross.linuxManualConfig {
  pname = "asterinas-reference-linux";
  inherit version;

  src = cross.fetchurl {
    url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${version}.tar.xz";
    hash = "sha256-ySYG+VbwncULWg4q+ehnY/zietoWR96X+NGsjPyVgB0=";
  };

  configfile = ./config;
  modDirVersion = version;

  extraMakeFlags = [
    "KBUILD_BUILD_USER=asterinas"
    "KBUILD_BUILD_HOST=qualification"
  ];
}
