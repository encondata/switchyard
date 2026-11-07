// Package secrets encrypts credentials at rest (spec §6) with AES-256-GCM
// and a key from the CPM_SECRET_KEY environment variable.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrNoKey means CPM_SECRET_KEY isn't set, so secrets can't be stored.
var ErrNoKey = errors.New("CPM_SECRET_KEY is not set; generate one with `openssl rand -base64 32` and restart CPM")

const prefix = "v1:"

// Box seals and opens secrets. A nil *Box has no key: Seal and Open fail
// with ErrNoKey.
type Box struct {
	aead cipher.AEAD
}

// ParseKey reads a 32-byte key given as base64 (standard or URL) or hex.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString, base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString, base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("CPM_SECRET_KEY must be 32 random bytes, base64 or hex encoded (`openssl rand -base64 32`)")
}

// New returns a Box for the key, or nil (no key) when key is empty.
func New(key string) (*Box, error) {
	if strings.TrimSpace(key) == "" {
		return nil, nil
	}
	k, err := ParseKey(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Ready reports whether the box has a key.
func (b *Box) Ready() bool { return b != nil }

// Seal encrypts plaintext. purpose is bound into the ciphertext (as GCM
// additional data), so a value sealed for one purpose won't open as another.
func (b *Box) Seal(plaintext, purpose string) (string, error) {
	if b == nil {
		return "", ErrNoKey
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(purpose))
	return prefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// Open decrypts a value from Seal.
func (b *Box) Open(sealed, purpose string) (string, error) {
	if b == nil {
		return "", ErrNoKey
	}
	if !strings.HasPrefix(sealed, prefix) {
		return "", errors.New("secrets: unknown format")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, prefix))
	if err != nil {
		return "", fmt.Errorf("secrets: %w", err)
	}
	n := b.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("secrets: value too short")
	}
	pt, err := b.aead.Open(nil, raw[:n], raw[n:], []byte(purpose))
	if err != nil {
		return "", errors.New("secrets: can't decrypt; was CPM_SECRET_KEY changed?")
	}
	return string(pt), nil
}
