package server

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestDefaultFaviconICOIsWellFormed verifies the embedded favicon is found and
// wrapped in a valid single-image ICO container.
func TestDefaultFaviconICOIsWellFormed(t *testing.T) {
	ico := defaultFaviconICO()
	if len(ico) <= 22 {
		t.Fatalf("favicon is %d bytes, expected an ICO header plus image data", len(ico))
	}
	if got := binary.LittleEndian.Uint16(ico[0:2]); got != 0 {
		t.Errorf("ICONDIR reserved = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint16(ico[2:4]); got != 1 {
		t.Errorf("ICONDIR type = %d, want 1 (icon)", got)
	}
	if got := binary.LittleEndian.Uint16(ico[4:6]); got != 1 {
		t.Errorf("ICONDIR count = %d, want 1", got)
	}
	if ico[6] != 32 || ico[7] != 32 {
		t.Errorf("ICONDIRENTRY size = %dx%d, want 32x32", ico[6], ico[7])
	}
	offset := binary.LittleEndian.Uint32(ico[18:22])
	if offset != 22 {
		t.Fatalf("image offset = %d, want 22", offset)
	}
	size := binary.LittleEndian.Uint32(ico[14:18])
	if int(offset)+int(size) != len(ico) {
		t.Fatalf("declared image size %d does not fill the container (%d bytes total)", size, len(ico))
	}
	if !bytes.HasPrefix(ico[offset:], []byte{0x89, 'P', 'N', 'G'}) {
		t.Error("payload is not the embedded PNG")
	}
}
