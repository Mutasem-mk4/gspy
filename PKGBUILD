# Maintainer: Mutasem Kharma <mutasem@gspy.dev>
# SPDX-License-Identifier: GPL-2.0-only
#
# PKGBUILD for gspy — forensic goroutine-to-syscall inspector
# Targets: BlackArch Linux, Arch Linux AUR
#
# Build requirements:
#   - go >= 1.21
#   - clang >= 14
#   - linux-headers (for vmlinux.h generation)
#   - bpf (for BPF bytecode compilation)

pkgname=gspy
pkgver=0.1.0
pkgrel=1
pkgdesc="Forensic goroutine-to-syscall inspector for live Go processes using eBPF"
arch=('x86_64')
url="https://github.com/Mutasem-mk4/gspy"
license=('GPL-2.0-only')
groups=('blackarch' 'blackarch-forensic' 'blackarch-debugger')
depends=('glibc')
makedepends=('go' 'clang' 'llvm' 'linux-headers' 'bpf')
source=("${pkgname}-${pkgver}.tar.gz::${url}/archive/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
    cd "${pkgname}-${pkgver}"

    # Generate vmlinux.h from running kernel's BTF data if available
    if [ -f /sys/kernel/btf/vmlinux ]; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
    fi

    # Generate BPF bytecode from C source
    export PATH="${PATH}:$(go env GOPATH)/bin"
    go install github.com/cilium/ebpf/cmd/bpf2go@v0.14.0

    cd internal/bpf
    bpf2go \
        -cc clang \
        -target bpfel \
        -type goroutine_meta \
        -type syscall_event \
        gspy ../../bpf/gspy.bpf.c -- \
        -I/usr/include \
        -I../../bpf \
        -O2 -g
    cd ../..

    # Build the Go binary with reproducible flags
    export CGO_ENABLED=0
    export GOFLAGS="-buildmode=pie -trimpath -mod=readonly -modcacherw"

    go build -trimpath \
        -ldflags="-s -w -X main.Version=${pkgver} -X main.BuildGoVersion=$(go version | awk '{print $3}')" \
        -o "${pkgname}" \
        ./cmd/gspy
}

check() {
    cd "${pkgname}-${pkgver}"
    # Tests use mock BPF layer — no root, no kernel, no BPF required
    go test -v -tags=testing ./...
}

package() {
    cd "${pkgname}-${pkgver}"

    # Binary
    install -Dm 755 "${pkgname}" "${pkgdir}/usr/bin/${pkgname}"

    # Man page
    install -Dm 644 "man/${pkgname}.1" "${pkgdir}/usr/share/man/man1/${pkgname}.1"

    # License
    install -Dm 644 LICENSE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"

    # Documentation
    install -Dm 644 README.md "${pkgdir}/usr/share/doc/${pkgname}/README.md"
}
