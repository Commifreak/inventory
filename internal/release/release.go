// Package release signs and verifies agent binaries.
//
// Agent binaries are signed with the publisher's Ed25519 key at build time
// (GitHub Actions secret RELEASE_SIGNING_KEY). The matching public key is
// compiled into every agent, so a compromised server cannot push modified
// binaries to agents.
//
// The signed message binds the binary hash to its version and platform:
//
//	inventory-agent-release-v1
//	<os>/<arch>
//	<version>
//	<hex sha256 of the binary>
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
)

//go:embed keys/*.pub
var keyFS embed.FS

// ExtraTrustedKey can be set at build time with
// -ldflags "-X github.com/commifreak/inventory/internal/release.ExtraTrustedKey=<base64 raw public key>"
// by people building their own images with their own signing key.
var ExtraTrustedKey string

const magic = "inventory-agent-release-v1"

// Message returns the byte string that is signed for a binary.
func Message(goos, goarch, version, sha256Hex string) []byte {
	return []byte(fmt.Sprintf("%s\n%s/%s\n%s\n%s\n", magic, goos, goarch, version, strings.ToLower(sha256Hex)))
}

// HashReader returns the hex SHA-256 and size of r.
func HashReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Sign creates a base64 signature.
func Sign(priv ed25519.PrivateKey, goos, goarch, version, sha256Hex string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Message(goos, goarch, version, sha256Hex)))
}

// Verify checks a signature against the given keys.
func Verify(keys []ed25519.PublicKey, goos, goarch, version, sha256Hex, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(keys) == 0 {
		return errors.New("no trusted keys")
	}
	msg := Message(goos, goarch, version, sha256Hex)
	for _, k := range keys {
		if ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return errors.New("signature does not match any trusted key")
}

// TrustedKeys returns the public keys compiled into this binary.
func TrustedKeys() []ed25519.PublicKey {
	var keys []ed25519.PublicKey
	entries, _ := keyFS.ReadDir("keys")
	for _, e := range entries {
		b, err := keyFS.ReadFile("keys/" + e.Name())
		if err != nil {
			continue
		}
		if k, err := ParsePublicKey(b); err == nil {
			keys = append(keys, k)
		}
	}
	if ExtraTrustedKey != "" {
		if raw, err := base64.StdEncoding.DecodeString(ExtraTrustedKey); err == nil && len(raw) == ed25519.PublicKeySize {
			keys = append(keys, ed25519.PublicKey(raw))
		} else if k, err := ParsePublicKey([]byte(ExtraTrustedKey)); err == nil {
			keys = append(keys, k)
		}
	}
	return keys
}

// ParsePublicKey parses a PEM (SubjectPublicKeyInfo) Ed25519 public key.
func ParsePublicKey(b []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}
	return pk, nil
}

// ParsePrivateKey parses a PEM (PKCS#8) Ed25519 private key as produced by
// "openssl genpkey -algorithm ed25519".
func ParsePrivateKey(b []byte) (ed25519.PrivateKey, error) {
	der, err := pemOrFlattened(b, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}
	return pk, nil
}

// pemOrFlattened decodes PEM. It also accepts PEM whose line breaks were
// lost (e.g. pasted into a single-line secret field).
func pemOrFlattened(b []byte, typ string) ([]byte, error) {
	if block, _ := pem.Decode(b); block != nil {
		return block.Bytes, nil
	}
	s := strings.TrimSpace(string(b))
	s = strings.TrimPrefix(s, "-----BEGIN "+typ+"-----")
	s = strings.TrimSuffix(s, "-----END "+typ+"-----")
	s = strings.Join(strings.Fields(s), "")
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(der) == 0 {
		return nil, errors.New("no PEM block")
	}
	return der, nil
}

// Manifest describes the agent binaries bundled with a server image.
// It is written to agents/<version>/manifest.json by the release tool.
type Manifest struct {
	Version  string   `json:"version"`
	Binaries []Binary `json:"binaries"`
}

// Binary is one platform build.
type Binary struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	File      string `json:"file"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Signature string `json:"signature,omitempty"` // empty = unsigned build
}
