// Package pgp implements the project-level GPG keypair management described
// in AI.md PART 11 "GPG Keypair Management". One Ed25519 (signing) +
// Curve25519 (encryption) keypair is generated per project, used to encrypt
// incoming security reports at rest, sign outbound notifications, and seed
// the Encryption: line in security.txt.
package pgp

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// KeyLifetime is the default keypair validity period per AI.md PART 11.
const KeyLifetime = 2 * 365 * 24 * time.Hour

// RotationGrace is how long a rotated-out key stays valid for in-flight
// reports per AI.md PART 11.
const RotationGrace = 30 * 24 * time.Hour

// Keypair holds a generated (or loaded) OpenPGP entity and its ASCII-armored
// serializations.
type Keypair struct {
	Entity      *openpgp.Entity
	Fingerprint string
	PublicArmor string
	// PrivateArmor is the ASCII-armored, UNENCRYPTED private key. Callers
	// must encrypt it (see security.EncryptWithSecret) before persisting.
	PrivateArmor string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// newConfig returns the packet.Config used for all key generation and
// signing in this package: EdDSA/Curve25519, SHA-512.
func newConfig() *packet.Config {
	return &packet.Config{
		DefaultHash:     crypto.SHA512,
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Curve:           packet.Curve25519,
		KeyLifetimeSecs: uint32(KeyLifetime / time.Second),
		SigLifetimeSecs: uint32(KeyLifetime / time.Second),
		Time:            time.Now,
	}
}

// Identity formats the OpenPGP user ID string per AI.md PART 11:
// "{app_name} Security <{security_contact}>".
func Identity(appName, securityContact string) string {
	return fmt.Sprintf("%s Security <%s>", appName, securityContact)
}

// Generate creates a new Ed25519 (signing) + Curve25519 (encryption)
// keypair with the given identity fields. See AI.md PART 11 "Generate".
func Generate(appName, securityContact string) (*Keypair, error) {
	cfg := newConfig()

	entity, err := openpgp.NewEntity(fmt.Sprintf("%s Security", appName), "", securityContact, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgp: generate entity: %w", err)
	}

	return finalize(entity, cfg)
}

// Rotate generates a fresh keypair and cross-signs it with the previous
// entity's primary key, per AI.md PART 11 "Rotate". old may be nil if there
// is no previous key to sign with (e.g. first-ever generation).
func Rotate(appName, securityContact string, old *openpgp.Entity) (*Keypair, error) {
	cfg := newConfig()

	entity, err := openpgp.NewEntity(fmt.Sprintf("%s Security", appName), "", securityContact, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgp: generate replacement entity: %w", err)
	}

	if old != nil {
		for name := range entity.Identities {
			if err := entity.SignIdentity(name, old, cfg); err != nil {
				return nil, fmt.Errorf("pgp: cross-sign new key with previous key: %w", err)
			}
		}
	}

	return finalize(entity, cfg)
}

// finalize serializes the public and private armored representations and
// extracts the fingerprint from a freshly generated entity.
func finalize(entity *openpgp.Entity, cfg *packet.Config) (*Keypair, error) {
	fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint)

	pubArmor, err := armorSerialize(entity.Serialize, openpgp.PublicKeyType)
	if err != nil {
		return nil, fmt.Errorf("pgp: armor public key: %w", err)
	}

	privArmor, err := armorSerialize(func(w io.Writer) error {
		return entity.SerializePrivate(w, cfg)
	}, openpgp.PrivateKeyType)
	if err != nil {
		return nil, fmt.Errorf("pgp: armor private key: %w", err)
	}

	now := time.Now()
	return &Keypair{
		Entity:       entity,
		Fingerprint:  fingerprint,
		PublicArmor:  pubArmor,
		PrivateArmor: privArmor,
		CreatedAt:    now,
		ExpiresAt:    now.Add(KeyLifetime),
	}, nil
}

// armorSerialize wraps a serialize function's output in ASCII armor.
func armorSerialize(serialize func(io.Writer) error, blockType string) (string, error) {
	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, blockType, nil)
	if err != nil {
		return "", err
	}
	if err := serialize(aw); err != nil {
		_ = aw.Close()
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ParsePrivate reads an ASCII-armored private key (as produced by Generate/
// Rotate, or imported from a backup) back into an openpgp.Entity.
func ParsePrivate(armored string) (*openpgp.Entity, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(armored)))
	if err != nil {
		return nil, fmt.Errorf("pgp: decode armor: %w", err)
	}
	if block.Type != openpgp.PrivateKeyType {
		return nil, fmt.Errorf("pgp: expected %q armor block, got %q", openpgp.PrivateKeyType, block.Type)
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		return nil, fmt.Errorf("pgp: read entity: %w", err)
	}
	return entity, nil
}

// Fingerprint returns the hex-encoded fingerprint of entity's primary key.
func Fingerprint(entity *openpgp.Entity) string {
	return hex.EncodeToString(entity.PrimaryKey.Fingerprint)
}

// ArmorPublic serializes entity's public key portion as ASCII armor. Used
// when importing a private-key-only backup, to reconstruct the matching
// public key for storage/publication.
func ArmorPublic(entity *openpgp.Entity) (string, error) {
	return armorSerialize(entity.Serialize, openpgp.PublicKeyType)
}
