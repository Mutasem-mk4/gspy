// SPDX-License-Identifier: GPL-2.0-only

package bpf

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRuntimeProbeOffsetsOnStrippedGoELF(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			plain, stripped := filepath.Join(dir, "plain"), filepath.Join(dir, "stripped")
			for _, build := range []struct{ path, flags string }{{plain, ""}, {stripped, "-s -w"}} {
				cmd := exec.Command("go", "build", "-ldflags="+build.flags, "-o", build.path, filepath.Join(dir, "main.go"))
				cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("build %s: %v\n%s", arch, err, output)
				}
			}
			offsets, err := runtimeProbeOffsets(stripped)
			if err != nil {
				t.Fatal(err)
			}
			f, err := elf.Open(plain)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			symbols, err := f.Symbols()
			if err != nil {
				t.Fatal(err)
			}
			for name, offset := range offsets {
				var want uint64
				for _, symbol := range symbols {
					if symbol.Name != name {
						continue
					}
					for _, segment := range f.Progs {
						if segment.Type == elf.PT_LOAD && symbol.Value >= segment.Vaddr && symbol.Value-segment.Vaddr < segment.Filesz {
							want = segment.Off + symbol.Value - segment.Vaddr
						}
					}
				}
				if want == 0 || offset != want {
					t.Fatalf("%s stripped offset = %#x, ELF symbol offset = %#x", name, offset, want)
				}
			}
		})
	}
}

func TestRuntimeProbeOffsetsRejectNonELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid")
	if err := os.WriteFile(path, []byte("not an executable"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeProbeOffsets(path); err == nil {
		t.Fatal("non-ELF target accepted")
	}
}
