# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>
#
# Makefile for gspy — forensic goroutine-to-syscall inspector
#
# Required tools:
#   - Go >= 1.26.8
#   - clang >= 14 (for BPF C compilation via bpf2go)
#   - bpftool (optional, for generating vmlinux.h)
#
# Typical workflow:
#   make generate   # compile BPF C → Go + .o bytecode
#   make build      # build the gspy binary
#   make test       # run tests (no root required)
#   make install    # install to /usr/bin and /usr/share/man

.PHONY: generate build install uninstall clean lint test man

# Version info
VERSION    ?= 0.2.1
GO_VERSION  = $(shell go version 2>/dev/null | awk '{print $$3}')
DESTDIR    ?=

# Build flags
LDFLAGS = -s -w \
	-X main.Version=$(VERSION) \
	-X main.BuildGoVersion=$(GO_VERSION)

# bpf2go is pinned by the go.mod tool directive and included by go mod vendor.
generate:
	GOOS=$(shell go env GOHOSTOS) GOARCH=$(shell go env GOHOSTARCH) go generate ./internal/bpf/...

# Build the gspy binary.
# Architectures supported: amd64, arm64 (set via GOARCH)
build: generate
	GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags="$(LDFLAGS)" -o bin/gspy ./cmd/gspy

# Build without generating BPF (for CI/testing when generated files exist).
build-only:
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/gspy ./cmd/gspy

# Install gspy binary and man page to system paths.
# Respects DESTDIR for package building (e.g., dpkg-buildpackage).
install: build
	install -Dm 0755 bin/gspy $(DESTDIR)/usr/bin/gspy
	install -Dm 0644 man/gspy.1 $(DESTDIR)/usr/share/man/man1/gspy.1

# Uninstall gspy binary and man page from system paths.
uninstall:
	rm -f $(DESTDIR)/usr/bin/gspy
	rm -f $(DESTDIR)/usr/share/man/man1/gspy.1

# Clean build artifacts and generated files.
clean:
	rm -rf bin/
	rm -f internal/bpf/gspy_bpfel*.go internal/bpf/gspy_bpfel*.o

# Run golangci-lint (requires golangci-lint installed).
lint:
	golangci-lint run ./...

# Run all tests.
# Tests use mock BPF layer — no root, no kernel, no BPF required.
# -race enables the race detector for concurrent code verification.
test:
	go test -v -race ./...

# Compress man page for distribution.
man:
	gzip -k man/gspy.1

# Generate vmlinux.h from the running kernel's BTF data.
# Only needed if vmlinux.h is not already present.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Vendor all dependencies for offline builds and distro packaging.
vendor:
	go mod vendor

# Cross-compilation check (build verification, not functional on non-Linux).
check-build:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o /dev/null ./cmd/gspy

# Quick development cycle: test + build.
dev: test build

# Prepare a source release containing dependencies for offline Debian builds.
source-dist:
	go mod vendor
	mkdir -p dist
	tar --exclude=.git --exclude=dist --exclude=bin --exclude='obj-*' --exclude=debian/gspy --exclude=debian/.debhelper -czf dist/gspy-$(VERSION)-source.tar.gz .
