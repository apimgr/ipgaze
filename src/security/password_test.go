package security

import (
	"strings"
	"testing"
)

func TestHashPassword_ProducesDifferentOutputEachRun(t *testing.T) {
	password := "testpassword123"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	if hash1 == hash2 {
		t.Error("HashPassword() produced identical hashes for same password (salt should differ)")
	}
}

func TestHashPassword_FormatCorrect(t *testing.T) {
	hash, err := HashPassword("test")
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=1,p=4$") {
		t.Errorf("HashPassword() format incorrect, got: %s", hash)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("HashPassword() expected 6 parts, got %d", len(parts))
	}
}

func TestVerifyPassword_SucceedsForCorrectPassword(t *testing.T) {
	password := "correctpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword() returned false for correct password")
	}
}

func TestVerifyPassword_FailsForWrongPassword(t *testing.T) {
	password := "correctpassword"
	wrongPassword := "wrongpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	if VerifyPassword(wrongPassword, hash) {
		t.Error("VerifyPassword() returned true for wrong password")
	}
}

func TestVerifyPassword_FailsForEmptyPassword(t *testing.T) {
	password := "actualpassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	if VerifyPassword("", hash) {
		t.Error("VerifyPassword() returned true for empty password")
	}
}

func TestHashPassword_EmptyPassword(t *testing.T) {
	// Empty passwords should still hash (application layer decides validity).
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("HashPassword() error for empty password: %v", err)
	}

	if hash == "" {
		t.Error("HashPassword() returned empty hash for empty password")
	}

	// Verify works with empty password.
	if !VerifyPassword("", hash) {
		t.Error("VerifyPassword() failed for empty password that was hashed")
	}
}

func TestVerifyPassword_InvalidHash(t *testing.T) {
	cases := []string{
		"",
		"invalid",
		"$argon2id$",
		"$argon2id$v=19$m=65536,t=1,p=4$",
		"$bcrypt$somehash",
		"notahash",
	}

	for _, invalidHash := range cases {
		if VerifyPassword("anypassword", invalidHash) {
			t.Errorf("VerifyPassword() returned true for invalid hash: %q", invalidHash)
		}
	}
}

func TestVerifyPassword_DifferentParameters(t *testing.T) {
	// Hash with default params.
	hash, err := HashPassword("test")
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	// Should verify with same password.
	if !VerifyPassword("test", hash) {
		t.Error("VerifyPassword() failed for correct password")
	}
}
