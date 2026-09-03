package log

import (
	"strings"
	"testing"
)

func TestNewULID_Format(t *testing.T) {
	id := newULID()
	if len(id) != 26 {
		t.Fatalf("newULID() length = %d, want 26 (got %q)", len(id), id)
	}
	for _, c := range id {
		if !strings.ContainsRune(crockford, c) {
			t.Errorf("newULID() contains char %q outside the Crockford alphabet", c)
		}
	}
	for _, ambiguous := range []rune{'I', 'L', 'O', 'U'} {
		if strings.ContainsRune(id, ambiguous) {
			t.Errorf("newULID() contains ambiguous char %q, want none of I/L/O/U", ambiguous)
		}
	}
}

func TestNewULID_Unique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id := newULID()
		if seen[id] {
			t.Fatalf("newULID() produced a duplicate: %q", id)
		}
		seen[id] = true
	}
}

func TestNewAuditID_PrefixAndLength(t *testing.T) {
	id := NewAuditID()
	if !strings.HasPrefix(id, "audit_") {
		t.Errorf("NewAuditID() = %q, want prefix %q", id, "audit_")
	}
	rest := strings.TrimPrefix(id, "audit_")
	if len(rest) != 26 {
		t.Errorf("NewAuditID() ULID portion length = %d, want 26 (got %q)", len(rest), rest)
	}
}
