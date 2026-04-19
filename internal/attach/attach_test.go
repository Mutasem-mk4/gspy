// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

package attach

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPIDValidation(t *testing.T) {
	// Set up mock /proc directory.
	tmpDir := t.TempDir()
	origProcPath := ProcPath
	ProcPath = tmpDir
	t.Cleanup(func() { ProcPath = origProcPath })

	// Create a mock /proc/<pid> directory for PID 1234.
	mockProcDir := filepath.Join(tmpDir, "1234")
	if err := os.MkdirAll(mockProcDir, 0755); err != nil {
		t.Fatalf("creating mock proc dir: %v", err)
	}

	tests := []struct {
		name    string
		pid     int
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid PID",
			pid:     1234,
			wantErr: false,
		},
		{
			name:    "nonexistent PID",
			pid:     9999,
			wantErr: true,
			errMsg:  "not found",
		},
		{
			name:    "PID zero",
			pid:     0,
			wantErr: true,
			errMsg:  "invalid PID",
		},
		{
			name:    "negative PID",
			pid:     -1,
			wantErr: true,
			errMsg:  "invalid PID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePID(tt.pid)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidatePID(%d) = nil, want error containing %q",
						tt.pid, tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidatePID(%d) error = %q, want containing %q",
						tt.pid, err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidatePID(%d) = %v, want nil", tt.pid, err)
				}
			}
		})
	}
}

func TestCapabilityCheck(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux-specific capability check test")
	}
	// Set up mock /proc directory.
	tmpDir := t.TempDir()
	origProcPath := ProcPath
	ProcPath = tmpDir
	t.Cleanup(func() { ProcPath = origProcPath })

	t.Run("missing_capabilities", func(t *testing.T) {
		// Create mock /proc/self/status with no capabilities.
		selfDir := filepath.Join(tmpDir, "self")
		if err := os.MkdirAll(selfDir, 0755); err != nil {
			t.Fatalf("creating mock self dir: %v", err)
		}

		// CapEff with no bits set = no capabilities.
		statusContent := `Name:	gspy
Umask:	0022
State:	S (sleeping)
Tgid:	1234
Pid:	1234
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
`
		statusPath := filepath.Join(selfDir, "status")
		if err := os.WriteFile(statusPath, []byte(statusContent), 0644); err != nil {
			t.Fatalf("writing mock status: %v", err)
		}

		err := CheckCapabilities()
		if err == nil {
			t.Error("CheckCapabilities() = nil, want error for missing capabilities")
			return
		}

		// Verify the error message mentions the required capabilities.
		errMsg := err.Error()
		if !contains(errMsg, "CAP_BPF") || !contains(errMsg, "CAP_PERFMON") {
			t.Errorf("error message should mention CAP_BPF and CAP_PERFMON, got: %q", errMsg)
		}
		if !contains(errMsg, "setcap") {
			t.Errorf("error message should show setcap command, got: %q", errMsg)
		}
	})

	t.Run("has_sys_admin", func(t *testing.T) {
		selfDir := filepath.Join(tmpDir, "self")
		// CAP_SYS_ADMIN = bit 21 → 0x200000
		statusContent := `Name:	gspy
CapEff:	0000000000200000
`
		statusPath := filepath.Join(selfDir, "status")
		if err := os.WriteFile(statusPath, []byte(statusContent), 0644); err != nil {
			t.Fatalf("writing mock status: %v", err)
		}

		err := CheckCapabilities()
		// On non-Linux, this will fail with "requires Linux" error.
		// On Linux, it should pass with CAP_SYS_ADMIN.
		if err != nil {
			errMsg := err.Error()
			if contains(errMsg, "CAP_BPF") {
				t.Errorf("should not fail on CAP_BPF when SYS_ADMIN is present: %v", err)
			}
		}
	})

	t.Run("has_bpf_and_perfmon", func(t *testing.T) {
		selfDir := filepath.Join(tmpDir, "self")
		// CAP_PERFMON = bit 38 → 0x4000000000
		// CAP_BPF     = bit 39 → 0x8000000000
		// Both:                   0xC000000000
		statusContent := `Name:	gspy
CapEff:	000000C000000000
`
		statusPath := filepath.Join(selfDir, "status")
		if err := os.WriteFile(statusPath, []byte(statusContent), 0644); err != nil {
			t.Fatalf("writing mock status: %v", err)
		}

		err := CheckCapabilities()
		if err != nil {
			errMsg := err.Error()
			if contains(errMsg, "CAP_BPF") {
				t.Errorf("should not fail when CAP_BPF+CAP_PERFMON are present: %v", err)
			}
		}
	})
}

// contains checks if s contains substr (case-sensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
