// Package tag embeds installer configuration (server URL, enrollment token)
// into an agent binary without rebuilding it.
//
// Unsigned binaries: the tag is appended to the end of the file
// ("overlay"). Executable formats ignore trailing data.
//
// Authenticode-signed Windows binaries: appending data after the signature
// would invalidate it. Signed builds are not produced yet; when they are,
// the tag will be stored inside the certificate table (the same technique
// Google uses for Chrome installers). Write returns ErrSigned until then.
//
// Layout of the overlay:
//
//	<payload JSON> <uint32 little endian payload length> "INVTAG01"
package tag

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/commifreak/inventory/internal/protocol"
)

const magic = "INVTAG01"

// MaxPayload bounds the tag size to keep reading cheap and safe.
const MaxPayload = 16 * 1024

var (
	// ErrNoTag is returned when a file carries no tag.
	ErrNoTag = errors.New("no install tag")
	// ErrSigned is returned when tagging an Authenticode-signed binary.
	ErrSigned = errors.New("tagging signed binaries is not supported yet")
)

// Append returns bin with the tag appended. An existing tag is replaced.
func Append(bin []byte, t protocol.InstallTag) ([]byte, error) {
	if signed, err := IsAuthenticodeSigned(bin); err == nil && signed {
		return nil, ErrSigned
	}
	payload, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxPayload {
		return nil, errors.New("tag too large")
	}
	base := Strip(bin)
	out := make([]byte, 0, len(base)+len(payload)+12)
	out = append(out, base...)
	out = append(out, payload...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	out = append(out, magic...)
	return out, nil
}

// Strip removes a tag if present.
func Strip(bin []byte) []byte {
	n, ok := tagLen(bin)
	if !ok {
		return bin
	}
	return bin[:len(bin)-12-n]
}

func tagLen(bin []byte) (int, bool) {
	if len(bin) < 12 || string(bin[len(bin)-8:]) != magic {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(bin[len(bin)-12 : len(bin)-8]))
	if n <= 0 || n > MaxPayload || n > len(bin)-12 {
		return 0, false
	}
	return n, true
}

// Read extracts the tag from bin.
func Read(bin []byte) (protocol.InstallTag, error) {
	var t protocol.InstallTag
	n, ok := tagLen(bin)
	if !ok {
		return t, ErrNoTag
	}
	payload := bin[len(bin)-12-n : len(bin)-12]
	if err := json.Unmarshal(payload, &t); err != nil {
		return t, fmt.Errorf("decode tag: %w", err)
	}
	return t, nil
}

// ReadFile extracts the tag from a file without loading it completely.
func ReadFile(path string) (protocol.InstallTag, error) {
	var t protocol.InstallTag
	f, err := os.Open(path)
	if err != nil {
		return t, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return t, err
	}
	size := st.Size()
	if size < 12 {
		return t, ErrNoTag
	}
	tail := int64(MaxPayload + 12)
	if tail > size {
		tail = size
	}
	buf := make([]byte, tail)
	if _, err := f.ReadAt(buf, size-tail); err != nil && err != io.EOF {
		return t, err
	}
	return Read(buf)
}

// IsAuthenticodeSigned reports whether bin is a PE file with a certificate table.
func IsAuthenticodeSigned(bin []byte) (bool, error) {
	f, err := pe.NewFile(bytes.NewReader(bin))
	if err != nil {
		return false, err
	}
	defer f.Close()
	const securityDir = 4 // IMAGE_DIRECTORY_ENTRY_SECURITY
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return len(oh.DataDirectory) > securityDir && oh.DataDirectory[securityDir].Size > 0, nil
	case *pe.OptionalHeader32:
		return len(oh.DataDirectory) > securityDir && oh.DataDirectory[securityDir].Size > 0, nil
	}
	return false, nil
}
