pkgbase=elogind-usersv
pkgname=('elogind-usersv' 'elogind-usersv-backend-s6-user' 'elogind-usersv-s6')
pkgver=0.2.0
pkgrel=1
pkgdesc='Elogind-specific per-user service-manager launcher and lifecycle supervisor'
arch=('x86_64')
url='https://github.com/username13121/elogind-usersv'
license=('GPL-3.0-only')
makedepends=('cargo')
options=('!debug')
_source_mtime='2026-08-28T00:00:00Z'
source=("$pkgbase-$pkgver.tar.gz::$url/releases/download/v$pkgver/$pkgbase-$pkgver.tar.gz")
sha256sums=('552e8fb76eb32d797702eadbfc89df1819ac0cb6c07997d955d6904ee1b81e5a')

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
    install=elogind-usersv.install
    optdepends=('elogind-usersv-backend-s6-user: s6-user per-user service-manager backend')
    backup=('etc/elogind-usersv/config.toml'
            'etc/pam.d/elogind-usersv-manager')

    cd "$pkgbase-$pkgver"
    install -Dm755 target/release/elogind-usersvd \
        "$pkgdir/usr/bin/elogind-usersvd"
    install -Dm755 target/release/elogind-usersv-supervisor \
        "$pkgdir/usr/libexec/elogind-usersv-supervisor"
    install -Dm755 target/release/libpam_elogind_usersv.so \
        "$pkgdir/usr/lib/security/pam_elogind_usersv.so"
    install -Dm755 target/release/elogind-usersv-pam \
        "$pkgdir/usr/bin/elogind-usersv-pam"

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

package_elogind-usersv-backend-s6-user() {
    pkgdesc='s6-user per-user service-manager backend for elogind-usersv'
    arch=('any')
    depends=('elogind-usersv' 's6' 's6-user')
    conflicts=('elogind-usersv-backend-s6')
    replaces=('elogind-usersv-backend-s6')

    cd "$pkgbase-$pkgver"
    install -Dm755 backends/s6-user \
        "$pkgdir/usr/libexec/elogind-usersv/backends/s6-user"
    install -Dm644 LICENSE \
        "$pkgdir/usr/share/licenses/elogind-usersv-backend-s6-user/LICENSE"
}

package_elogind-usersv-s6() {
    pkgdesc='s6-rc system service definition for elogind-usersv'
    arch=('any')
    groups=('s6-world')
    depends=('elogind-usersv' 's6-base')
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
