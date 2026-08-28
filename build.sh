#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$project_root"

pkgver=$(awk -F= '$1 == "pkgver" { print $2; exit }' PKGBUILD)
source_mtime=$(awk -F"'" '$1 ~ /^_source_mtime=/ { print $2; exit }' PKGBUILD)
pkgbase=elogind-usersv
source_dir="$project_root/.sources"
build_dir="$project_root/.build"
package_dir="$project_root/packages"
source_archive="$source_dir/$pkgbase-$pkgver.tar.gz"

usage() {
    cat <<'EOF'
Usage: ./build.sh [--clean]

Builds this standalone elogind-usersv repository into ./packages.
  --clean    remove local package/build/source output before building
EOF
}

clean=false
for argument in "$@"; do
    case $argument in
        --clean) clean=true ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $argument" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ $EUID -eq 0 ]]; then
    echo 'build.sh: makepkg must not be run as root' >&2
    exit 1
fi

if $clean; then
    rm -rf -- "$build_dir" "$source_dir" "$package_dir"
fi
mkdir -p -- "$source_dir" "$build_dir" "$package_dir"
rm -f -- "$package_dir"/elogind-usersv-*.pkg.tar.*

# Create the same deterministic, packaging-file-free source archive attached
# to the GitHub release. Excluding PKGBUILD avoids a checksum self-reference.
temporary_archive="$source_archive.tmp"
rm -f -- "$temporary_archive"
tar -C "$project_root" \
    --sort=name \
    --mtime="$source_mtime" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --pax-option=delete=atime,delete=ctime \
    --exclude=.git \
    --exclude=.gitignore \
    --exclude=.SRCINFO \
    --exclude=.build \
    --exclude=.sources \
    --exclude=packages \
    --exclude=target \
    --exclude=PKGBUILD \
    --exclude=build.sh \
    --transform="s,^,$pkgbase-$pkgver/," \
    -cf - . | gzip -n >"$temporary_archive"
mv -- "$temporary_archive" "$source_archive"

BUILDDIR="$build_dir" \
SRCDEST="$source_dir" \
PKGDEST="$package_dir" \
makepkg --cleanbuild --clean --force --nodeps
cp -- "$source_archive" "$package_dir/"

(
    cd "$package_dir"
    sha256sum -- *.pkg.tar.zst >SHA256SUMS
)
echo "==> Release artifacts and SHA256SUMS are in $package_dir"
