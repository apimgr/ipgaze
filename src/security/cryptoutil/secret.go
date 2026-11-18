package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func deriveAESKey(secret []byte, info string) ([]byte, error) {
	kdf := hkdf.New(sha256.New, secret, nil, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("security: derive key: %w", err)
	}
	return key, nil
}

// EncryptWithSecret encrypts plaintext with AES-256-GCM using HKDF-SHA256 and
// returns nonce followed by ciphertext.
func EncryptWithSecret(secret, plaintext []byte, info string) ([]byte, error) {
	key, err := deriveAESKey(secret, info)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("security: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("security: new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("security: generate nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptWithSecret decrypts ciphertext produced by EncryptWithSecret.
func DecryptWithSecret(secret, ciphertext []byte, info string) ([]byte, error) {
	key, err := deriveAESKey(secret, info)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("security: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("security: new gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("security: ciphertext too short")
	}
	nonce, sealed := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, sealed, nil)
}
