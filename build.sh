#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$project_root"

pkgver=$(awk -F= '$1 == "pkgver" { print $2; exit }' PKGBUILD)
pkgbase=elogind-usersv
source_dir="$project_root/.sources"
build_dir="$project_root/.build"
package_dir="$project_root/packages"
source_archive="$source_dir/$pkgbase-$pkgver.tar.gz"

usage() {
    cat <<EOF
Usage: ./build.sh [--clean] [--install]

Builds this standalone elogind-usersv repository into ./packages.
  --clean    remove local package/build/source output before building
  --install  install all freshly built split packages with pacman -U
EOF
}

clean=false
install_packages=false
for argument in "$@"; do
    case $argument in
        --clean) clean=true ;;
        --install) install_packages=true ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $argument" >&2; usage >&2; exit 2 ;;
    esac
done

if $clean; then
    rm -rf -- "$build_dir" "$source_dir" "$package_dir"
fi
mkdir -p -- "$source_dir" "$build_dir" "$package_dir"
rm -f -- "$package_dir"/elogind-usersv-*.pkg.tar.*

# Supply a release-shaped archive from the current working tree so local
# source and PKGBUILD changes can be tested before they are committed.
tar -C "$project_root" \
    --exclude=.git \
    --exclude=.build \
    --exclude=.sources \
    --exclude=packages \
    --exclude=target \
    --transform="s,^,$pkgbase-$pkgver/," \
    -czf "$source_archive" .

BUILDDIR="$build_dir" \
SRCDEST="$source_dir" \
PKGDEST="$package_dir" \
makepkg --cleanbuild --syncdeps --noconfirm

mapfile -t built_packages < <(
    find "$package_dir" -maxdepth 1 -type f \
        -name 'elogind-usersv-*.pkg.tar.*' ! -name '*.sig' -print | sort
)
if (( ${#built_packages[@]} == 0 )); then
    echo 'No elogind-usersv packages were produced.' >&2
    exit 1
fi

printf '\nBuilt packages:\n'
printf '  %s\n' "${built_packages[@]}"
printf '\nInstall the standalone elogind-usersv package set with:\n  sudo pacman -U'
printf ' %q' "${built_packages[@]}"
printf '\n'

if $install_packages; then
    sudo pacman -U --needed "${built_packages[@]}"
fi
