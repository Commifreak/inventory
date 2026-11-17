// Command inventory-release creates the signed manifest for agent binaries
// and manages publisher keys.
//
//	inventory-release manifest -dir dist/agents/1.2.3 -version 1.2.3 [-key key.pem]
//	inventory-release keygen -out release-signing        (writes .key and .pub)
//	inventory-release verify -dir dist/agents/1.2.3 [-pub key.pub]
//
// The private key is read from -key, RELEASE_SIGNING_KEY_FILE or
// RELEASE_SIGNING_KEY (PEM content). Without a key the manifest is written
// unsigned: agents then refuse such builds as updates.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/commifreak/inventory/internal/release"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: inventory-release manifest|keygen|verify [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "manifest":
		err = manifest(os.Args[2:])
	case "keygen":
		err = keygen(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

var binRe = regexp.MustCompile(`^inventory-agent-(windows|linux|darwin)-(amd64|arm64|arm)(\.exe)?$`)

func loadKey(path string) (ed25519.PrivateKey, error) {
	var pemData []byte
	switch {
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		pemData = b
	case os.Getenv("RELEASE_SIGNING_KEY_FILE") != "":
		b, err := os.ReadFile(os.Getenv("RELEASE_SIGNING_KEY_FILE"))
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		pemData = b
	case os.Getenv("RELEASE_SIGNING_KEY") != "":
		pemData = []byte(os.Getenv("RELEASE_SIGNING_KEY"))
	}
	if len(strings.TrimSpace(string(pemData))) == 0 {
		return nil, nil
	}
	return release.ParsePrivateKey(pemData)
}

func manifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	dir := fs.String("dir", "", "directory with agent binaries")
	version := fs.String("version", "", "agent version")
	keyPath := fs.String("key", "", "private key (PEM)")
	requireSig := fs.Bool("require-signature", false, "fail without a signing key")
	_ = fs.Parse(args)
	if *dir == "" || *version == "" {
		return fmt.Errorf("-dir and -version are required")
	}
	key, err := loadKey(*keyPath)
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	if key == nil && *requireSig {
		return fmt.Errorf("no signing key available")
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	m := release.Manifest{Version: *version}
	for _, e := range entries {
		mm := binRe.FindStringSubmatch(e.Name())
		if mm == nil {
			continue
		}
		f, err := os.Open(filepath.Join(*dir, e.Name()))
		if err != nil {
			return err
		}
		sum, n, err := release.HashReader(f)
		f.Close()
		if err != nil {
			return err
		}
		b := release.Binary{OS: mm[1], Arch: mm[2], File: e.Name(), SHA256: sum, Size: n}
		if key != nil {
			b.Signature = release.Sign(key, b.OS, b.Arch, *version, sum)
		}
		m.Binaries = append(m.Binaries, b)
	}
	if len(m.Binaries) == 0 {
		return fmt.Errorf("no agent binaries found in %s", *dir)
	}
	sort.Slice(m.Binaries, func(i, j int) bool { return m.Binaries[i].File < m.Binaries[j].File })
	out, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(*dir, "manifest.json"), out, 0o644); err != nil {
		return err
	}
	state := "UNSIGNED"
	if key != nil {
		state = "signed"
	}
	fmt.Printf("manifest: %d binaries, version %s, %s\n", len(m.Binaries), *version, state)
	return nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "release-signing", "output file prefix")
	_ = fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDer, _ := x509.MarshalPKIXPublicKey(pub)
	if err := os.WriteFile(*out+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s.key (keep secret) and %s.pub\n", *out, *out)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("dir", "", "directory with manifest.json")
	pubPath := fs.String("pub", "", "public key (default: keys compiled into this tool)")
	_ = fs.Parse(args)
	b, err := os.ReadFile(filepath.Join(*dir, "manifest.json"))
	if err != nil {
		return err
	}
	var m release.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	keys := release.TrustedKeys()
	if *pubPath != "" {
		pb, err := os.ReadFile(*pubPath)
		if err != nil {
			return err
		}
		k, err := release.ParsePublicKey(pb)
		if err != nil {
			return err
		}
		keys = []ed25519.PublicKey{k}
	}
	bad := 0
	for _, bin := range m.Binaries {
		f, err := os.Open(filepath.Join(*dir, bin.File))
		if err != nil {
			return err
		}
		sum, _, _ := release.HashReader(f)
		f.Close()
		status := "ok"
		switch {
		case sum != bin.SHA256:
			status = "HASH MISMATCH"
		case bin.Signature == "":
			status = "unsigned"
		case release.Verify(keys, bin.OS, bin.Arch, m.Version, sum, bin.Signature) != nil:
			status = "BAD SIGNATURE"
		}
		if status != "ok" {
			bad++
		}
		fmt.Printf("%-40s %s\n", bin.File, status)
	}
	if bad > 0 {
		return fmt.Errorf("%d binaries failed verification", bad)
	}
	return nil
}
