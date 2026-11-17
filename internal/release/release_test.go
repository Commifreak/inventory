package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := Sign(priv, "windows", "amd64", "1.2.3", "ABCDEF")
	keys := []ed25519.PublicKey{pub}
	if err := Verify(keys, "windows", "amd64", "1.2.3", "abcdef", sig); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][3]string{{"linux", "amd64", "1.2.3"}, {"windows", "arm64", "1.2.3"}, {"windows", "amd64", "1.2.4"}} {
		if Verify(keys, c[0], c[1], c[2], "abcdef", sig) == nil {
			t.Fatalf("signature accepted for %v", c)
		}
	}
}

func TestKeys(t *testing.T) {
	if len(TrustedKeys()) == 0 {
		t.Fatal("no embedded publisher key")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	k, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil || !k.Equal(priv) {
		t.Fatalf("parse private key: %v", err)
	}
}

func TestFlattenedPEM(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	p := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	flat := strings.ReplaceAll(p, "\n", " ")
	if k, err := ParsePrivateKey([]byte(flat)); err != nil || !k.Equal(priv) {
		t.Fatalf("flattened PEM: %v", err)
	}
}
