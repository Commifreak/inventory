package server

import (
	"fmt"
	"testing"

	"github.com/commifreak/inventory/internal/protocol"
)

func TestSoftwareChanges(t *testing.T) {
	sw := func(name, ver string) protocol.SoftwareItem {
		return protocol.SoftwareItem{Name: name, Version: ver, Source: "registry", Scope: "machine"}
	}
	summary := func(prev, cur []protocol.SoftwareItem) []string {
		var out []string
		for _, c := range softwareChanges(prev, cur) {
			out = append(out, fmt.Sprintf("%s %s %s>%s", c.Change, c.Name, c.VersionOld, c.VersionNew))
		}
		return out
	}
	cases := []struct {
		name      string
		prev, cur []protocol.SoftwareItem
		want      []string
	}{
		{"unchanged", []protocol.SoftwareItem{sw("A", "1")}, []protocol.SoftwareItem{sw("A", "1")}, nil},
		{"update", []protocol.SoftwareItem{sw("A", "1")}, []protocol.SoftwareItem{sw("A", "2")}, []string{"updated A 1>2"}},
		{"install and remove", []protocol.SoftwareItem{sw("A", "1")}, []protocol.SoftwareItem{sw("B", "1")}, []string{"installed B >1", "removed A 1>"}},
		// Two uninstall entries with the same name must not produce a
		// change on every report, regardless of their order.
		{"duplicate unchanged", []protocol.SoftwareItem{sw("A", "26"), sw("A", "25")}, []protocol.SoftwareItem{sw("A", "25"), sw("A", "26")}, nil},
		{"duplicate one updated", []protocol.SoftwareItem{sw("A", "26"), sw("A", "25")}, []protocol.SoftwareItem{sw("A", "27"), sw("A", "25")}, []string{"updated A 26>27"}},
		{"duplicate entry removed", []protocol.SoftwareItem{sw("A", "26"), sw("A", "25")}, []protocol.SoftwareItem{sw("A", "26")}, []string{"removed A 25>"}},
		{"duplicate entry added", []protocol.SoftwareItem{sw("A", "26")}, []protocol.SoftwareItem{sw("A", "26"), sw("A", "25")}, []string{"installed A >25"}},
	}
	for _, tc := range cases {
		got := summary(tc.prev, tc.cur)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
