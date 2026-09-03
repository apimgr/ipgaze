// Package security provides cryptographic utilities for ipgaze.
// See AI.md PART 11 for security requirements.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per AI.md PART 11 recommendations.
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// ErrInvalidHash is returned when a hash string cannot be parsed.
var ErrInvalidHash = errors.New("invalid argon2id hash format")

// HashPassword hashes a password using Argon2id.
// Returns an encoded string in the format:
// $argon2id$v=19$m=65536,t=1,p=4$salt$hash
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Encode in PHC string format.
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory,
		argon2Time,
		argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// VerifyPassword verifies a password against an Argon2id hash.
// Uses constant-time comparison per AI.md PART 11.
func VerifyPassword(password, encodedHash string) bool {
	salt, hash, params, err := decodeHash(encodedHash)
	if err != nil {
		return false
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.threads,
		uint32(len(hash)),
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1
}

type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
}

// decodeHash parses a PHC-format Argon2id hash string.
func decodeHash(encodedHash string) (salt, hash []byte, params argon2Params, err error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		err = ErrInvalidHash
		return
	}

	if parts[1] != "argon2id" {
		err = ErrInvalidHash
		return
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		err = ErrInvalidHash
		return
	}

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads)
	if err != nil {
		err = ErrInvalidHash
		return
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		err = ErrInvalidHash
		return
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		err = ErrInvalidHash
		return
	}

	return salt, hash, params, nil
}
