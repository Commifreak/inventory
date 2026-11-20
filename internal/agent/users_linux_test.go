package agent

import (
	"strings"
	"testing"
)

func TestParseLoginctlSessions(t *testing.T) {
	out := `[{"session":"3","uid":1000,"user":"administrator","seat":null,"leader":1234,"class":"user","tty":"pts/0","idle":false,"since":null},
{"session":"4","uid":1000,"user":"administrator","seat":null,"leader":1240,"class":"manager","tty":null,"idle":false,"since":null},
{"session":"c1","uid":120,"user":"gdm","seat":"seat0","leader":900,"class":"greeter","tty":"tty1","idle":false,"since":null},
{"session":"5","uid":1001,"user":"anna","seat":"seat0","leader":1500,"class":"user","tty":"tty2","idle":false,"since":null}]`
	if got := strings.Join(parseLoginctlSessions(out), ","); got != "administrator,anna" {
		t.Errorf("users: %s", got)
	}
	if parseLoginctlSessions("No sessions.") != nil {
		t.Error("non-JSON output not ignored")
	}
}

func TestParseLogindJournal(t *testing.T) {
	out := `2026-11-18T08:02:11+0100 ai systemd-logind[812]: New session 1 of user administrator.
2026-11-18T08:05:00+0100 ai systemd-logind[812]: New session c1 of user gdm.
2026-11-20T19:51:40+0100 ai systemd-logind[812]: New session 3 of user administrator.
2026-11-20T19:52:01+0100 ai systemd-logind[812]: Session 3 logged out. Waiting for processes to exit.
2026-11-19T10:00:00+0100 ai systemd-logind[812]: New session 2 of user root.`
	l := parseLogindJournal(out, func(u string) bool { return u == "gdm" })
	if len(l) != 2 || l[0].User != "administrator" || l[0].Time.Format("2006-01-02 15:04") != "2026-11-20 19:51" || l[1].User != "root" {
		t.Errorf("logons: %+v", l)
	}
}
