package config

import "testing"

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"10KB", 10 * 1024, false},
		{"5MB", 5 * 1024 * 1024, false},
		{"1GB", 1 << 30, false},
		{"1TB", 1 << 40, false},
		{"500B", 500, false},
		{"100", 100, false},
		{" 10 KB ", 10 * 1024, false},
		{"", 0, true},
		{"notasize", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseByteSize(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseByteSize(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("ParseByteSize(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestDebugConfig_MaxBodyLogSizeBytes(t *testing.T) {
	tests := []struct {
		name string
		size string
		want int64
	}{
		{"valid size", "20KB", 20 * 1024},
		{"empty falls back to default", "", 10 * 1024},
		{"invalid falls back to default", "garbage", 10 * 1024},
		{"zero falls back to default", "0B", 10 * 1024},
		{"negative falls back to default", "-1B", 10 * 1024},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DebugConfig{MaxBodyLogSize: tt.size}
			if got := d.MaxBodyLogSizeBytes(); got != tt.want {
				t.Errorf("MaxBodyLogSizeBytes() = %d, want %d", got, tt.want)
			}
		})
	}
}
