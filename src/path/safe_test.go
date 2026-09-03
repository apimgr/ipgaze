package path

import (
	"testing"
)

func TestSafePath(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		path     string
		wantErr  bool
		errType  error
		wantPath string
	}{
		{
			name:     "valid simple path",
			base:     "/data",
			path:     "file.txt",
			wantErr:  false,
			wantPath: "/data/file.txt",
		},
		{
			name:     "valid nested path",
			base:     "/data",
			path:     "subdir/file.txt",
			wantErr:  false,
			wantPath: "/data/subdir/file.txt",
		},
		{
			name:     "empty path returns base",
			base:     "/data",
			path:     "",
			wantErr:  false,
			wantPath: "/data",
		},
		{
			name:    "traversal with ..",
			base:    "/data",
			path:    "../etc/passwd",
			wantErr: true,
			errType: ErrPathTraversal,
		},
		{
			name:    "traversal with ../ in middle",
			base:    "/data",
			path:    "subdir/../../../etc/passwd",
			wantErr: true,
			errType: ErrPathTraversal,
		},
		{
			name:    "encoded traversal %2e%2e",
			base:    "/data",
			path:    "%2e%2e/etc/passwd",
			wantErr: true,
			errType: ErrPathTraversal,
		},
		{
			name:    "encoded traversal ..%2f",
			base:    "/data",
			path:    "..%2fetc/passwd",
			wantErr: true,
			errType: ErrPathTraversal,
		},
		{
			name:    "null byte injection",
			base:    "/data",
			path:    "file.txt\x00.jpg",
			wantErr: true,
			errType: ErrPathTraversal,
		},
		{
			name:    "empty base",
			base:    "",
			path:    "file.txt",
			wantErr: true,
			errType: ErrInvalidPath,
		},
		{
			name:    "backslash traversal",
			base:    "/data",
			path:    "..\\etc\\passwd",
			wantErr: true,
			errType: ErrPathTraversal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafePath(tt.base, tt.path)
			if tt.wantErr {
				if err == nil {
					t.Errorf("SafePath() expected error, got nil")
					return
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("SafePath() error = %v, want %v", err, tt.errType)
				}
				return
			}
			if err != nil {
				t.Errorf("SafePath() unexpected error = %v", err)
				return
			}
			if got != tt.wantPath {
				t.Errorf("SafePath() = %v, want %v", got, tt.wantPath)
			}
		})
	}
}

func TestNormalizeURLPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"empty path", "", "/"},
		{"root path", "/", "/"},
		{"simple path", "/api/v1", "/api/v1"},
		{"double slashes", "/api//v1//test", "/api/v1/test"},
		{"trailing slash", "/api/v1/", "/api/v1"},
		{"no leading slash", "api/v1", "/api/v1"},
		{"backslashes", "/api\\v1", "/api/v1"},
		{"mixed slashes", "/api\\\\v1//test/", "/api/v1/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeURLPath(tt.path)
			if got != tt.want {
				t.Errorf("NormalizeURLPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPathSafe(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"simple path", "/api/v1/test", true},
		{"with dot file", "/api/.config", true},
		{"traversal ..", "/api/../etc", false},
		{"traversal ..%2f", "/api/..%2fetc", false},
		{"encoded traversal", "/api/%2e%2e/etc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPathSafe(tt.path)
			if got != tt.want {
				t.Errorf("IsPathSafe() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{"valid filename", "file.txt", false},
		{"valid with numbers", "file123.txt", false},
		{"valid with dash", "my-file.txt", false},
		{"valid with underscore", "my_file.txt", false},
		{"empty filename", "", true},
		{"dot dot", "..", true},
		{"single dot", ".", true},
		{"starts with ..", "..hidden", true},
		{"contains slash", "path/file.txt", true},
		{"contains backslash", "path\\file.txt", true},
		{"null byte", "file\x00.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilename(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilename() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
