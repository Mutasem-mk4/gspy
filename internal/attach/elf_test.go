// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

package attach

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

func TestGIDOffsetTable(t *testing.T) {
	// Verify offset lookup returns correct value for Go 1.17 through 1.23.
	tests := []struct {
		goVersion  string
		wantOffset uint64
		wantKnown  bool
	}{
		{"go1.17", 152, true},
		{"go1.17.13", 152, true},
		{"go1.18", 152, true},
		{"go1.18.10", 152, true},
		{"go1.19", 152, true},
		{"go1.19.7", 152, true},
		{"go1.20", 152, true},
		{"go1.20.14", 152, true},
		{"go1.21", 152, true},
		{"go1.21.5", 152, true},
		{"go1.22", 152, true},
		{"go1.22.0", 152, true},
		{"go1.22rc1", 152, true},
		{"go1.23", 152, true},
		{"go1.23.4", 152, true},
		{"go1.24", 152, true},
		{"go1.24.0", 152, true},
	}

	for _, tt := range tests {
		t.Run(tt.goVersion, func(t *testing.T) {
			// Use empty binary path (DWARF lookup will fail, falls back to table).
			offset, warning := GetGIDOffset("", tt.goVersion)

			if offset != tt.wantOffset {
				t.Errorf("GetGIDOffset(%q) offset = %d, want %d",
					tt.goVersion, offset, tt.wantOffset)
			}

			if tt.wantKnown && warning != "" {
				// Warning is OK if it's just the DWARF fallback notice,
				// but should NOT contain "unknown Go version".
				if searchString(warning, "unknown Go version") {
					t.Errorf("GetGIDOffset(%q) should be known, got warning: %s",
						tt.goVersion, warning)
				}
			}
		})
	}

	// Test unknown version — should return fallback offset with warning.
	t.Run("unknown_version", func(t *testing.T) {
		offset, warning := GetGIDOffset("", "go1.99.0")

		if offset != DefaultGIDOffset {
			t.Errorf("GetGIDOffset(unknown) offset = %d, want %d",
				offset, DefaultGIDOffset)
		}

		if warning == "" {
			t.Error("GetGIDOffset(unknown) should return a warning")
		}

		if !searchString(warning, "unknown") && !searchString(warning, "WARNING") {
			t.Errorf("warning should mention unknown version, got: %s", warning)
		}
	})

	// Test unparseable version.
	t.Run("unparseable_version", func(t *testing.T) {
		offset, warning := GetGIDOffset("", "notaversion")

		if offset != DefaultGIDOffset {
			t.Errorf("GetGIDOffset(unparseable) offset = %d, want %d",
				offset, DefaultGIDOffset)
		}

		if warning == "" {
			t.Error("GetGIDOffset(unparseable) should return a warning")
		}
	})
}

func TestGoVersionParse(t *testing.T) {
	tests := []struct {
		input     string
		wantMajor int
		wantMinor int
		wantErr   bool
	}{
		{"go1.17", 1, 17, false},
		{"go1.17.13", 1, 17, false},
		{"go1.18", 1, 18, false},
		{"go1.18.10", 1, 18, false},
		{"go1.19", 1, 19, false},
		{"go1.20", 1, 20, false},
		{"go1.21", 1, 21, false},
		{"go1.21.5", 1, 21, false},
		{"go1.22", 1, 22, false},
		{"go1.22rc1", 1, 22, false},
		{"go1.22beta1", 1, 22, false},
		{"go1.23", 1, 23, false},
		{"go1.23.4", 1, 23, false},
		{"go1.24", 1, 24, false},
		{"go1.24.0", 1, 24, false},
		{"go2.0", 2, 0, false},
		// Error cases
		{"notaversion", 0, 0, true},
		{"", 0, 0, true},
		{"go", 0, 0, true},
		{"go1", 0, 0, true},
		{"1.21", 0, 0, true}, // missing "go" prefix
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			major, minor, err := ParseGoVersion(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseGoVersion(%q) = (%d, %d, nil), want error",
						tt.input, major, minor)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseGoVersion(%q) error = %v, want nil", tt.input, err)
				return
			}

			if major != tt.wantMajor || minor != tt.wantMinor {
				t.Errorf("ParseGoVersion(%q) = (%d, %d), want (%d, %d)",
					tt.input, major, minor, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestSHA256Binary(t *testing.T) {
	// Create a temporary file with known content.
	tmpFile, err := os.CreateTemp(t.TempDir(), "test-binary-*")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer tmpFile.Close()

	content := []byte("hello world — test binary content for SHA-256 verification")
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	tmpFile.Close()

	// Compute SHA-256 using our function.
	got, err := ComputeSHA256(tmpFile.Name())
	if err != nil {
		t.Fatalf("ComputeSHA256() error = %v", err)
	}

	// Compute expected SHA-256 independently.
	h := sha256.Sum256(content)
	want := fmt.Sprintf("%x", h[:])

	if got != want {
		t.Errorf("ComputeSHA256() = %q, want %q", got, want)
	}

	// Verify it's a valid hex string of correct length.
	if len(got) != 64 {
		t.Errorf("SHA-256 hash length = %d, want 64", len(got))
	}

	// Test nonexistent file.
	_, err = ComputeSHA256("/nonexistent/file/path")
	if err == nil {
		t.Error("ComputeSHA256(nonexistent) should return error")
	}
}

func TestDWARFLookupGoidOffset_NoFile(t *testing.T) {
	// DWARF lookup on a nonexistent file should return an error.
	_, err := DWARFLookupGoidOffset("/nonexistent/binary")
	if err == nil {
		t.Error("DWARFLookupGoidOffset(nonexistent) should return error")
	}
}

func TestIsGoVersion(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"go1.21.5", true},
		{"go1.17", true},
		{"go2.0", true},
		{"notgo", false},
		{"", false},
		{"go", false},
		{"go1", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := IsGoVersion(tt.input); got != tt.want {
				t.Errorf("IsGoVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSupportedGoVersionRange(t *testing.T) {
	r := SupportedGoVersionRange()
	if r == "" {
		t.Error("SupportedGoVersionRange() should return non-empty string")
	}
	if !searchString(r, "1.17") || !searchString(r, "1.24") {
		t.Errorf("SupportedGoVersionRange() = %q, should mention 1.17 and 1.24", r)
	}
}
