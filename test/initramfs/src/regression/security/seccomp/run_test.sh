#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

./install
./filter
./trap
./tsync
