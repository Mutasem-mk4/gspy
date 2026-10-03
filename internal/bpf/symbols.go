// SPDX-License-Identifier: GPL-2.0-only

package bpf

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
)

// runtimeProbeOffsets resolves file offsets from Go's PC table, which remains
// present when the ELF symbol table is removed by go build -ldflags='-s -w'.
func runtimeProbeOffsets(path string) (offsets map[string]uint64, err error) {
	// The standard gosym parser assumes compiler-generated input. A malformed
	// target must produce an attachment error rather than crash the tracer.
	defer func() {
		if recovered := recover(); recovered != nil {
			offsets = nil
			err = fmt.Errorf("invalid Go PC table: %v", recovered)
		}
	}()
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pcln, text := f.Section(".gopclntab"), f.Section(".text")
	if pcln == nil || text == nil {
		return nil, fmt.Errorf("missing Go PC table or text section")
	}
	data, err := pcln.Data()
	if err != nil {
		return nil, fmt.Errorf("reading Go PC table: %w", err)
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, text.Addr))
	if err != nil {
		return nil, fmt.Errorf("parsing Go PC table: %w", err)
	}
	offsets = make(map[string]uint64, 3)
	for _, name := range []string{"runtime.execute", "runtime.newproc1", "runtime.goexit1"} {
		fn := table.LookupFunc(name)
		if fn == nil {
			return nil, fmt.Errorf("Go PC table lacks %s", name)
		}
		for _, segment := range f.Progs {
			if segment.Type == elf.PT_LOAD && segment.Flags&elf.PF_X != 0 &&
				fn.Entry >= segment.Vaddr && fn.Entry-segment.Vaddr < segment.Filesz {
				offsets[name] = segment.Off + fn.Entry - segment.Vaddr
				break
			}
		}
		if offsets[name] == 0 {
			return nil, fmt.Errorf("%s is outside executable file segments", name)
		}
	}
	return offsets, nil
}
