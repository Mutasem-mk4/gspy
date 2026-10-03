// SPDX-License-Identifier: GPL-2.0-only
package attach

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Compile real targets independently of the toolchain running the test suite.
// CI sets this explicitly for every supported modern runtime release.
func TestCompiledRuntimeLayout(t *testing.T) {
	toolchain := os.Getenv("GSPY_ABI_TOOLCHAIN")
	if toolchain == "" {
		t.Skip("set GSPY_ABI_TOOLCHAIN to verify a compiled Go runtime")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module abi.test\n\ngo 1.17\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "target.go")
	if err := os.WriteFile(source, []byte("package main\nimport \"runtime\"\nfunc main(){runtime.Gosched()}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			binary := filepath.Join(dir, "target-"+arch)
			stripped := binary + "-stripped"
			for _, build := range []struct{ path, flags string }{{binary, ""}, {stripped, "-s -w"}} {
				command := exec.Command("go", "build", "-ldflags", build.flags, "-o", build.path, source)
				command.Dir = dir
				command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOTOOLCHAIN="+toolchain)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("build %s: %v\n%s", toolchain, err, output)
				}
			}
			version, err := DetectGoVersion(binary)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := DWARFLookupGoidOffset(binary)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s linux/%s runtime.g.goid = %d", version, arch, actual)
			fallback, diagnostic := GetGIDOffset(stripped, version)
			if diagnostic != "" || fallback != actual {
				t.Fatalf("stripped binary: offset=%d diagnostic=%q; DWARF=%d", fallback, diagnostic, actual)
			}
		})
	}
}

func TestUnsupportedELFRefusedEvenWithDWARF(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "target.go")
	if err := os.WriteFile(source, []byte("package main\nimport \"runtime\"\nfunc main(){runtime.Gosched()}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "target-386")
	command := exec.Command("go", "build", "-o", binary, source)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=386", "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build unsupported ELF: %v\n%s", err, output)
	}
	if _, err := DWARFLookupGoidOffset(binary); err != nil {
		t.Fatalf("fixture must have readable runtime DWARF: %v", err)
	}
	offset, diagnostic := GetGIDOffset(binary, "go1.26.8")
	if offset != 0 || !strings.Contains(diagnostic, "unsupported target architecture") {
		t.Fatalf("must refuse unsupported ELF before using DWARF: offset=%d diagnostic=%q", offset, diagnostic)
	}
}
