pkgbase=elogind-usersv
pkgname=('elogind-usersv' 'elogind-usersv-backend-s6' 'elogind-usersv-s6')
pkgver=0.1.0
pkgrel=1
pkgdesc='Elogind-specific per-user service-manager launcher and lifecycle supervisor'
arch=('x86_64')
url='https://github.com/username13121/elogind-usersv'
license=('GPL-3.0-only')
makedepends=('cargo')
options=('!debug')
source=("$pkgbase-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$pkgbase-$pkgver"
    cargo build --release --locked --workspace
}

check() {
    cd "$pkgbase-$pkgver"
    cargo test --locked --workspace
}

package_elogind-usersv() {
    depends=('elogind' 'gcc-libs' 'glibc' 'pam')
    optdepends=('elogind-usersv-backend-s6: per-user s6-svscan and s6-rc backend')
    backup=('etc/elogind-usersv/config.toml'
            'etc/pam.d/elogind-usersv-manager')

    cd "$pkgbase-$pkgver"
    install -Dm755 target/release/elogind-usersvd \
        "$pkgdir/usr/sbin/elogind-usersvd"
    install -Dm755 target/release/elogind-usersv-supervisor \
        "$pkgdir/usr/libexec/elogind-usersv-supervisor"
    install -Dm755 target/release/libpam_elogind_usersv.so \
        "$pkgdir/usr/lib/security/pam_elogind_usersv.so"

    install -Dm644 config/config.toml \
        "$pkgdir/etc/elogind-usersv/config.toml"
    install -dm755 "$pkgdir/etc/elogind-usersv/backends"
    install -Dm644 pam.d/elogind-usersv-manager \
        "$pkgdir/etc/pam.d/elogind-usersv-manager"

    install -Dm644 README.md \
        "$pkgdir/usr/share/doc/elogind-usersv/README.md"
    install -Dm644 pam.d/login-stack-example \
        "$pkgdir/usr/share/doc/elogind-usersv/login-stack-example"
    for document in docs/*.md; do
        install -Dm644 "$document" \
            "$pkgdir/usr/share/doc/elogind-usersv/${document##*/}"
    done
    install -Dm644 LICENSE \
        "$pkgdir/usr/share/licenses/elogind-usersv/LICENSE"
}

package_elogind-usersv-backend-s6() {
    pkgdesc='s6-svscan and s6-rc backend for elogind-usersv'
    depends=('elogind-usersv' 's6-user')

    cd "$pkgbase-$pkgver"
    install -Dm755 backends/s6 \
        "$pkgdir/usr/libexec/elogind-usersv/backends/s6"
    install -Dm644 LICENSE \
        "$pkgdir/usr/share/licenses/elogind-usersv-backend-s6/LICENSE"
}

package_elogind-usersv-s6() {
    pkgdesc='s6-rc system service definition for elogind-usersv'
    groups=('s6-world')
    depends=('elogind' 'elogind-usersv' 'elogind-usersv-backend-s6' 's6-base')
    provides=('init-elogind-usersv')
    conflicts=('init-elogind-usersv')

    cd "$pkgbase-$pkgver"
    install -Dm644 integration/s6-rc/elogind-usersvd/type \
        "$pkgdir/etc/s6/sv/elogind-usersvd/type"
    install -Dm755 integration/s6-rc/elogind-usersvd/run \
        "$pkgdir/etc/s6/sv/elogind-usersvd/run"
    install -Dm644 integration/s6-rc/elogind-usersvd/dependencies.d/elogind \
        "$pkgdir/etc/s6/sv/elogind-usersvd/dependencies.d/elogind"
    install -Dm644 LICENSE \
        "$pkgdir/usr/share/licenses/elogind-usersv-s6/LICENSE"
}
