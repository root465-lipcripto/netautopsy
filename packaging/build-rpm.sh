#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version=0.1.0
cd "$root"
top=$(mktemp -d)
trap 'rm -r -- "$top"' EXIT
mkdir -p "$top/SOURCES" dist
git archive --format=tar.gz --prefix="netautopsy-$version/" HEAD \
    > "$top/SOURCES/netautopsy-$version.tar.gz"
rpmbuild "$@" -bb --define "_topdir $top" packaging/netautopsy.spec
cp -- "$top"/RPMS/*/netautopsy-*.rpm dist/
(
    cd dist
    sha256sum "netautopsy-$version"-*.rpm > SHA256SUMS
)
