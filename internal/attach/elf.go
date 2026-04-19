// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

package attach

import (
	"crypto/sha256"
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// GID Offset Table
// ---------------------------------------------------------------------------
//
// These offsets represent the byte offset of the `goid` field (type int64)
// within the `runtime.g` struct on amd64 Linux. They are verified against
// the Go runtime source code at:
//   https://github.com/golang/go/blob/goX.YZ/src/runtime/runtime2.go
//
// The runtime.g struct layout is ABI-sensitive and may change between Go
// versions. When the struct changes, the goid offset shifts. However, from
// Go 1.17 through Go 1.23, the offset has remained stable at 152 bytes on
// amd64.
//
// WARNING: These offsets are verified ONLY for amd64. On arm64 and other
// architectures, the offsets may differ due to alignment and padding.
// When running on non-amd64, gspy will log a clear warning.
//
// If DWARF debug info is available in the target binary, gspy always
// prefers DWARF-derived offsets over this table.

var gidOffsetTable = map[string]uint64{
	// Go 1.17: https://github.com/golang/go/blob/go1.17/src/runtime/runtime2.go#L422
	"1.17": 152,
	// Go 1.18: https://github.com/golang/go/blob/go1.18/src/runtime/runtime2.go#L422
	"1.18": 152,
	// Go 1.19: https://github.com/golang/go/blob/go1.19/src/runtime/runtime2.go#L422
	"1.19": 152,
	// Go 1.20: https://github.com/golang/go/blob/go1.20/src/runtime/runtime2.go#L428
	"1.20": 152,
	// Go 1.21: https://github.com/golang/go/blob/go1.21.0/src/runtime/runtime2.go#L428
	"1.21": 152,
	// Go 1.22: https://github.com/golang/go/blob/go1.22.0/src/runtime/runtime2.go#L445
	"1.22": 152,
	// Go 1.23: https://github.com/golang/go/blob/go1.23.0/src/runtime/runtime2.go#L445
	"1.23": 152,
	// Go 1.24: https://github.com/golang/go/blob/go1.24.0/src/runtime/runtime2.go#L445
	"1.24": 152,
}

// DefaultGIDOffset is the fallback offset used when the Go version is unknown
// and DWARF lookup fails. Based on the most common offset across versions.
const DefaultGIDOffset uint64 = 152

// DetectGoVersion reads the target binary's ELF build information to extract
// the Go version string (e.g., "go1.21.5").
//
// Uses debug/buildinfo.ReadFile which parses the .go.buildinfo ELF section.
// This requires the binary to be a Go binary (built with Go 1.13+).
func DetectGoVersion(binaryPath string) (string, error) {
	info, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return "", fmt.Errorf("reading build info from %s: %w",
			binaryPath, err)
	}

	if info.GoVersion == "" {
		return "", fmt.Errorf("Go version not found in build info of %s",
			binaryPath)
	}

	return info.GoVersion, nil
}

// goVersionRe matches strings like "go1.21", "go1.21.5", "go1.21rc1".
var goVersionRe = regexp.MustCompile(`^go(\d+)\.(\d+)`)

// ParseGoVersion extracts the major.minor version from a Go version string.
// Input examples: "go1.21.5", "go1.22rc1", "go1.17"
// Returns (major, minor, nil) or an error if parsing fails.
func ParseGoVersion(version string) (int, int, error) {
	matches := goVersionRe.FindStringSubmatch(version)
	if len(matches) < 3 {
		return 0, 0, fmt.Errorf("cannot parse Go version %q", version)
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, fmt.Errorf("parsing Go major version %q: %w",
			matches[1], err)
	}

	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return 0, 0, fmt.Errorf("parsing Go minor version %q: %w",
			matches[2], err)
	}

	return major, minor, nil
}

// GetGIDOffset returns the goid field offset for the given Go version.
// It first attempts a DWARF lookup in the target binary (most accurate),
// then falls back to the hardcoded offset table, and finally to
// DefaultGIDOffset with a warning.
//
// Returns (offset, warning_message). Warning is empty if offset is confirmed.
func GetGIDOffset(binaryPath string, goVersion string) (uint64, string) {
	// Step 1: Try DWARF lookup (most accurate, always preferred).
	if offset, err := DWARFLookupGoidOffset(binaryPath); err == nil {
		return offset, ""
	}

	// Step 2: Check architecture.
	var archWarning string
	if runtime.GOARCH != "amd64" {
		archWarning = fmt.Sprintf(
			"WARNING: goid offsets are verified only for amd64; "+
				"current arch is %s — offset may be incorrect. "+
				"Consider providing a binary with DWARF debug info.",
			runtime.GOARCH)
	}

	// Step 3: Parse version and look up in table.
	_, minor, err := ParseGoVersion(goVersion)
	if err != nil {
		warning := fmt.Sprintf(
			"WARNING: could not parse Go version %q, "+
				"using default goid offset %d",
			goVersion, DefaultGIDOffset)
		if archWarning != "" {
			warning = archWarning + "\n" + warning
		}
		return DefaultGIDOffset, warning
	}

	// Construct major.minor key (e.g., "1.21")
	key := fmt.Sprintf("1.%d", minor)
	if offset, ok := gidOffsetTable[key]; ok {
		return offset, archWarning
	}

	// Step 4: Unknown version — use default with warning.
	warning := fmt.Sprintf(
		"WARNING: unknown Go version %s (parsed as %s), "+
			"using default goid offset %d — goroutine IDs may be incorrect",
		goVersion, key, DefaultGIDOffset)
	if archWarning != "" {
		warning = archWarning + "\n" + warning
	}
	return DefaultGIDOffset, warning
}

// DWARFLookupGoidOffset searches the DWARF debug information in the target
// binary for the runtime.g type and returns the offset of the goid field.
//
// This is the most accurate method as it reads the actual compiled layout.
// It requires the binary to contain DWARF info (not stripped).
//
// DWARF lookup procedure:
//  1. Open the ELF binary and extract DWARF data
//  2. Iterate through all DWARF entries looking for DW_TAG_structure_type
//     with name "runtime.g"
//  3. Within that struct, find DW_TAG_member with name "goid"
//  4. Read DW_AT_data_member_loc to get the field offset
func DWARFLookupGoidOffset(binaryPath string) (uint64, error) {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return 0, fmt.Errorf("opening ELF %s: %w", binaryPath, err)
	}
	defer f.Close()

	d, err := f.DWARF()
	if err != nil {
		return 0, fmt.Errorf("reading DWARF from %s: %w", binaryPath, err)
	}

	r := d.Reader()

	for {
		entry, err := r.Next()
		if err != nil {
			return 0, fmt.Errorf("reading DWARF entries: %w", err)
		}
		if entry == nil {
			break
		}

		// Look for DW_TAG_structure_type with name "runtime.g"
		if entry.Tag != dwarf.TagStructType {
			continue
		}

		nameField := entry.AttrField(dwarf.AttrName)
		if nameField == nil {
			continue
		}

		name, ok := nameField.Val.(string)
		if !ok || name != "runtime.g" {
			continue
		}

		// Found runtime.g — now search for the goid member.
		if !entry.Children {
			continue
		}

		for {
			child, err := r.Next()
			if err != nil {
				return 0, fmt.Errorf("reading DWARF children: %w", err)
			}
			if child == nil || child.Tag == 0 {
				break // end of children
			}

			if child.Tag != dwarf.TagMember {
				continue
			}

			memberName := child.AttrField(dwarf.AttrName)
			if memberName == nil {
				continue
			}

			mname, ok := memberName.Val.(string)
			if !ok || mname != "goid" {
				continue
			}

			// Found goid — read DW_AT_data_member_loc.
			locField := child.AttrField(dwarf.AttrDataMemberLoc)
			if locField == nil {
				return 0, fmt.Errorf(
					"goid field found but DW_AT_data_member_loc missing")
			}

			switch v := locField.Val.(type) {
			case int64:
				return uint64(v), nil
			case uint64:
				return v, nil
			case []byte:
				// DWARF location expression — parse simple constant form.
				// DW_OP_plus_uconst followed by ULEB128 offset.
				if len(v) >= 2 && v[0] == 0x23 { // DW_OP_plus_uconst
					offset, _ := decodeULEB128(v[1:])
					return offset, nil
				}
				return 0, fmt.Errorf(
					"unsupported DWARF location expression for goid")
			default:
				return 0, fmt.Errorf(
					"unexpected DW_AT_data_member_loc type %T", v)
			}
		}
	}

	return 0, fmt.Errorf("goid field not found in DWARF info of %s",
		binaryPath)
}

// decodeULEB128 decodes an unsigned LEB128 value from a byte slice.
func decodeULEB128(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, b := range data {
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
		if shift >= 64 {
			break
		}
	}
	return result, len(data)
}

// ComputeSHA256 computes the SHA-256 hash of the file at the given path.
// Used in --readonly mode to verify target binary integrity.
func ComputeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening %s for SHA-256: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("computing SHA-256 of %s: %w", path, err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// IsGoVersion checks if a version string looks like a valid Go version.
func IsGoVersion(s string) bool {
	return strings.HasPrefix(s, "go1.") || strings.HasPrefix(s, "go2.")
}

// SupportedGoVersionRange returns the range of Go versions with verified offsets.
func SupportedGoVersionRange() string {
	return "1.17 – 1.24 (amd64 verified)"
}
