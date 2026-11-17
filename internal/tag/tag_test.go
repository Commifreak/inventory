package tag

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/commifreak/inventory/internal/protocol"
)

func TestAppendReadStrip(t *testing.T) {
	bin := []byte("MZ\x90\x00 not really a PE file")
	if _, err := Read(bin); err != ErrNoTag {
		t.Fatalf("expected ErrNoTag, got %v", err)
	}
	want := protocol.InstallTag{ServerURL: "https://inv.example.com", EnrollmentToken: "tok"}
	tagged, err := Append(bin, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(tagged)
	if err != nil || got != want {
		t.Fatalf("read %+v %v", got, err)
	}
	// Re-tagging replaces the tag instead of stacking it.
	again, _ := Append(tagged, protocol.InstallTag{ServerURL: "https://other", EnrollmentToken: "x"})
	if !bytes.Equal(Strip(again), bin) {
		t.Fatal("strip did not restore the original binary")
	}
	p := filepath.Join(t.TempDir(), "a.exe")
	_ = os.WriteFile(p, tagged, 0o644)
	if got, err := ReadFile(p); err != nil || got != want {
		t.Fatalf("ReadFile %+v %v", got, err)
	}
}
