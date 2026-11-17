package agent

import "testing"

func TestServiceLabel(t *testing.T) {
	cases := map[[2]string]string{
		{"SysMain", "SysMain"}: "SysMain",
		{"Microsoft Edge Update Service (edgeupdate)", "edgeupdate"}: "Microsoft Edge Update Service (edgeupdate)",
		{"AppX-Bereitstellungsdienst (AppXSVC)", "AppXSvc"}:          "AppX-Bereitstellungsdienst (AppXSVC)",
		{"Druckwarteschlange", "Spooler"}:                            "Druckwarteschlange (Spooler)",
		{"", "foo"}:                                                  "foo",
	}
	for in, want := range cases {
		if got := serviceLabel(in[0], in[1]); got != want {
			t.Errorf("serviceLabel(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
