package proc

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStrippedGoBinaryRetainsFunctionNames(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "target.go")
	if err := os.WriteFile(source, []byte(`package main
import "fmt"
//go:noinline
func work() { fmt.Println("fixture") }
func main() { work() }
`), 0600); err != nil {
		t.Fatal(err)
	}
	binaries := []string{filepath.Join(directory, "symbols"), filepath.Join(directory, "stripped")}
	for index, binary := range binaries {
		args := []string{"build", "-o", binary}
		if index == 1 {
			args = append(args, "-ldflags=-s -w")
		}
		command := exec.Command("go", append(args, source)...)
		command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("compile fixture: %v\n%s", err, output)
		}
	}
	reference, err := elf.Open(binaries[0])
	if err != nil {
		t.Fatal(err)
	}
	defer reference.Close()
	symbols, err := reference.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	var pc uint64
	for _, symbol := range symbols {
		if symbol.Name == "main.work" {
			pc = symbol.Value + 1
		}
	}
	if pc == 0 {
		t.Fatal("reference fixture lacks main.work")
	}
	stripped, err := elf.Open(binaries[1])
	if err != nil {
		t.Fatal(err)
	}
	defer stripped.Close()
	if _, err := stripped.Symbols(); err != elf.ErrNoSymbols {
		t.Fatalf("fixture is not stripped: %v", err)
	}
	for _, binary := range binaries {
		resolver, err := NewFrameResolver(binary, NewSymbolCache(100))
		if err != nil {
			t.Fatal(err)
		}
		if got := resolver.Resolve(pc); got != "main.work" {
			t.Fatalf("%s: resolve captured PC = %q, want main.work", binary, got)
		}
		if got := resolver.Resolve(1); got != "0x1" {
			t.Fatalf("invalid PC should remain visibly unresolved, got %q", got)
		}
	}
}
