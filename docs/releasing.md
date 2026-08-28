# Release procedure

Release only after `make test`, `make test-live` on Artix, and the documented
login lifecycle checks pass.

1. Update workspace/package versions and `_source_mtime` in `PKGBUILD`.
2. Run `./build.sh --clean`.
3. Confirm the deterministic source archive checksum equals `sha256sums` in
   `PKGBUILD`; update it and rebuild if source content changed.
4. Regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO`.
5. Verify `packages/SHA256SUMS` and inspect every package with `pacman -Qip`
   and `pacman -Qlp`.
6. Commit, tag the immutable version, and push it.
7. Create the GitHub Release and upload every file in `packages/`: the three
   unsigned packages, deterministic source archive, and `SHA256SUMS`.

The PKGBUILD downloads the deterministic source archive from the release asset,
not GitHub's generated source snapshot. Do not move an existing release tag or
replace an uploaded source archive without issuing a new release.
