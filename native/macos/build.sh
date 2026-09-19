#!/bin/sh
# Builds the macOS authentication helper into native/bin/ecv-auth.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../bin"
mkdir -p "$out"

swiftc -O -swift-version 5 "$here/ecv-auth.swift" -o "$out/ecv-auth"
# Ad-hoc signature so Keychain ACLs stay stable for this binary.
codesign --force --sign - "$out/ecv-auth"
echo "built $out/ecv-auth"
