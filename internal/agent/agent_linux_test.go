package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
	"github.com/commifreak/inventory/internal/release"
	"github.com/commifreak/inventory/internal/server"
)

// TestAgentLifecycle runs the agent against a real server: enrollment,
// reporting, signed update download, self test and binary swap.
func TestAgentLifecycle(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	release.ExtraTrustedKey = base64.StdEncoding.EncodeToString(pub)
	defer func() { release.ExtraTrustedKey = "" }()

	// A fake "new agent" that passes the self test.
	const newVersion = "9.9.9"
	bundle := filepath.Join(dir, "bundle", newVersion)
	_ = os.MkdirAll(bundle, 0o755)
	script := []byte("#!/bin/sh\necho " + newVersion + "\n")
	file := "inventory-agent-linux-" + runtimeArch()
	_ = os.WriteFile(filepath.Join(bundle, file), script, 0o755)
	sum, n, _ := release.HashReader(bytes.NewReader(script))
	m := release.Manifest{Version: newVersion, Binaries: []release.Binary{{OS: "linux", Arch: runtimeArch(), File: file, SHA256: sum, Size: n,
		Signature: release.Sign(priv, "linux", runtimeArch(), newVersion, sum)}}}
	mb, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(bundle, "manifest.json"), mb, 0o644)

	srv, err := server.New(server.Config{DataDir: filepath.Join(dir, "server"), AgentsDir: filepath.Join(dir, "bundle"), InitialAdminPassword: "x-initial-password",
		LocalLogin: true, SessionLifetime: time.Hour, Version: "test"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	token := srv.FirstActiveToken(t.Context())

	// Agent installation layout.
	testRoot = filepath.Join(dir, "agent")
	defer func() { testRoot = "" }()
	_ = os.MkdirAll(filepath.Dir(BinaryPath()), 0o755)
	_ = os.WriteFile(BinaryPath(), []byte("old binary"), 0o755)
	if err := SaveConfig(&Config{ServerURL: ts.URL, EnrollmentToken: token}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := LoadConfig()
	a := &Agent{cfg: cfg, state: LoadState(), log: slog.New(slog.NewTextHandler(io.Discard, nil)), client: NewClient(cfg.ServerURL, ""),
		colls: map[string]Collector{
			protocol.CollectSoftware: func(context.Context, *State) (any, []string, error) {
				return protocol.SoftwareData{Items: []protocol.SoftwareItem{{Name: "bash", Version: "5.2", Source: "dpkg"}}}, nil, nil
			},
			protocol.CollectSMART: func(context.Context, *State) (any, []string, error) { return nil, nil, errors.New("no smartctl") },
		}}
	Version = "1.0.0"
	defer func() { Version = "dev" }()

	_, err = a.cycle(t.Context())
	if !errors.Is(err, ErrRestart) {
		t.Fatalf("expected restart after update, got %v", err)
	}
	if a.cfg.DeviceID == "" || a.cfg.EnrollmentToken != "" {
		t.Fatalf("enrollment not persisted: %+v", a.cfg)
	}
	got, _ := os.ReadFile(BinaryPath())
	if !bytes.Equal(got, script) {
		t.Fatalf("binary not replaced: %q", got)
	}
	if old, _ := os.ReadFile(BinaryPath() + ".old"); string(old) != "old binary" {
		t.Fatal("old binary not kept")
	}
	st := LoadState()
	if st.PendingUpdate == nil || st.PendingUpdate.To != newVersion {
		t.Fatalf("pending update not recorded: %+v", st.PendingUpdate)
	}
	if !st.LastRun[protocol.CollectSoftware].After(time.Now().Add(-time.Minute)) {
		t.Fatal("software collector did not run")
	}

	// The "new" process starts: the update is confirmed at the next check-in.
	Version = newVersion
	a2 := &Agent{cfg: cfg, state: LoadState(), log: a.log, client: NewClient(ts.URL, a.cfg.Credential), colls: map[string]Collector{}}
	if err := a2.checkPendingUpdate(); err != nil {
		t.Fatal(err)
	}
	if a2.state.UpdateResult == nil || !a2.state.UpdateResult.Success {
		t.Fatalf("update result: %+v", a2.state.UpdateResult)
	}
	if _, err := a2.cycle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if a2.state.PendingUpdate != nil || fileExists(BinaryPath()+".old") {
		t.Fatal("update not finalised")
	}

	// A tampered offer is rejected.
	bad := &protocol.UpdateOffer{Version: newVersion, SHA256: sum, Size: n, Signature: release.Sign(priv, "linux", runtimeArch(), "6.6.6", sum)}
	if err := VerifyBinary(BinaryPath(), bad); err == nil {
		t.Fatal("signature for another version accepted")
	}
}

func TestParseSmartctlATA(t *testing.T) {
	out := []byte(`{"smartctl":{"version":[7,5],"exit_status":0},"device":{"name":"/dev/sda","type":"sat","protocol":"ATA"},
"model_name":"Samsung SSD 870 EVO 1TB","serial_number":"S6PU123","firmware_version":"SVT02B6Q","user_capacity":{"bytes":1000204886016},
"rotation_rate":0,"smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true},"temperature":{"current":31},
"power_on_time":{"hours":12000},"power_cycle_count":800,
"ata_smart_attributes":{"table":[{"id":5,"name":"Reallocated_Sector_Ct","value":100,"worst":100,"thresh":10,"when_failed":"","raw":{"value":2,"string":"2"}},
{"id":197,"name":"Current_Pending_Sector","value":100,"worst":100,"thresh":0,"when_failed":"","raw":{"value":0,"string":"0"}},
{"id":199,"name":"UDMA_CRC_Error_Count","value":100,"worst":100,"thresh":0,"when_failed":"past","raw":{"value":5,"string":"5"}}]}}`)
	d, err := ParseSmartctl(out)
	if err != nil {
		t.Fatal(err)
	}
	if d.Model != "Samsung SSD 870 EVO 1TB" || d.MediaType != "SSD" || d.Bus != "SATA" || *d.Reallocated != 2 || *d.Pending != 0 || *d.CRCErrors != 5 ||
		*d.Temperature != 31 || *d.PowerOnHours != 12000 || !*d.HealthPassed || d.Attributes[2].Failing != "past" {
		t.Fatalf("unexpected %+v", d)
	}
}

func TestParseSmartctlNVMe(t *testing.T) {
	out := []byte(`{"smartctl":{"version":[7,5],"exit_status":4,"messages":[{"string":"Read Self-test Log failed","severity":"error"}]},
"device":{"name":"/dev/nvme0","type":"nvme","protocol":"NVMe"},"model_name":"WD_BLACK SN770 1TB","serial_number":"22123","nvme_total_capacity":1000204886016,
"smart_status":{"passed":true},"nvme_smart_health_information_log":{"critical_warning":0,"temperature":41,"available_spare":100,"available_spare_threshold":10,
"percentage_used":3,"data_units_written":20000000,"power_cycles":500,"power_on_hours":3000,"unsafe_shutdowns":20,"media_errors":0}}`)
	d, err := ParseSmartctl(out)
	if err != nil {
		t.Fatal(err)
	}
	if d.Protocol != "NVMe" || *d.PercentUsed != 3 || *d.Temperature != 41 || *d.PowerOnHours != 3000 || d.SizeBytes == 0 || len(d.Messages) != 1 {
		t.Fatalf("unexpected %+v", d)
	}
	if tb := *d.DataWrittenTB; tb < 10.2 || tb > 10.3 {
		t.Fatalf("data written %f", tb)
	}
}

func TestParseKernelEvents(t *testing.T) {
	lines := []string{
		`{"MESSAGE":"Out of memory: Killed process 1234 (java) total-vm:100kB","__REALTIME_TIMESTAMP":"1700000000000000"}`,
		`{"MESSAGE":"blk_update_request: I/O error, dev sdb, sector 123","__REALTIME_TIMESTAMP":"1700000001000000"}`,
		`{"MESSAGE":"I/O error, dev sdb, sector 124","__REALTIME_TIMESTAMP":"1700000002000000"}`,
		`{"MESSAGE":"I/O error, dev loop3, sector 1","__REALTIME_TIMESTAMP":"1700000003000000"}`,
		`{"MESSAGE":[69,88,84,52,45,102,115,32,101,114,114,111,114,32,40,100,101,118,105,99,101,32,115,100,97,49,41],"__REALTIME_TIMESTAMP":"1700000100000000"}`,
		`{"MESSAGE":"usb 1-1: new device","__REALTIME_TIMESTAMP":"1700000200000000"}`,
	}
	evs := ParseKernelEvents(lines)
	if len(evs) != 3 {
		t.Fatalf("expected 3 events, got %+v", evs)
	}
	if evs[0].Kind != protocol.EventOOM || evs[1].Kind != protocol.EventDiskError || evs[1].Device != "sdb" || evs[2].Device != "sda1" {
		t.Fatalf("unexpected %+v", evs)
	}
	if !bytes.Contains([]byte(evs[1].Message), []byte("+1 similar")) {
		t.Fatalf("grouping failed: %s", evs[1].Message)
	}
}

func TestParseWindowsEvents(t *testing.T) {
	xml := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WER-SystemErrorReporting'/><EventID>1001</EventID>
<TimeCreated SystemTime='2026-11-10T08:00:00.0000000Z'/><EventRecordID>4711</EventRecordID></System><EventData><Data>0x0000007e</Data></EventData>
<RenderingInfo Culture='de-DE'><Message>Der Computer wurde nach einem schwerwiegenden Fehler neu gestartet.</Message></RenderingInfo></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='disk'/><EventID>7</EventID>
<TimeCreated SystemTime='2026-11-11T08:00:00.0000000Z'/><EventRecordID>4712</EventRecordID></System><EventData><Data>\Device\Harddisk1\DR1</Data></EventData></Event>`
	// wevtutil /uni:true output is UTF-16LE.
	var u16 []byte
	for _, r := range xml {
		u16 = append(u16, byte(r), byte(r>>8))
	}
	evs, err := ParseWindowsEvents(decodeUTF16(u16))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].Kind != protocol.EventBluescreen || evs[0].Key != "evt|4711" || evs[1].Kind != protocol.EventDiskError || evs[1].Device != `\Device\Harddisk1\DR1` {
		t.Fatalf("unexpected %+v", evs)
	}
}

func runtimeArch() string { return runtime.GOARCH }

func TestKernelEventsSDCardAndDmesg(t *testing.T) {
	boot := time.Date(2026, 11, 17, 6, 0, 0, 0, time.UTC)
	raw := "[  100.000001] mmc0: Timeout waiting for hardware interrupt.\n" +
		"[  100.500000] mmcblk0: error -110 transferring data, sector 1234, nr 8, cmd response 0x900\n" +
		"[  101.000000] I/O error, dev mmcblk0, sector 1234 op 0x1:(WRITE) flags 0x0\n" +
		"[  200.000000] EXT4-fs warning (device mmcblk0p2): ext4_end_bio:342: I/O error 10 writing to inode 1234\n" +
		"[  300.000000] usb 1-1.2: new high-speed USB device\n"
	recs := parseDmesgRaw(raw, boot)
	if len(recs) != 5 || !recs[0].t.Equal(boot.Add(100*time.Second)) {
		t.Fatalf("raw dmesg: %+v", recs)
	}
	iso := parseDmesgISO("2026-11-17T06:01:40,000001+00:00 mmc0: Timeout waiting for hardware interrupt.\n")
	if len(iso) != 1 || !iso[0].t.Equal(boot.Add(100*time.Second+time.Microsecond)) {
		t.Fatalf("iso dmesg: %+v", iso)
	}
	// The same line from the journal is not counted twice.
	journal := journalRecords([]string{`{"MESSAGE":"I/O error, dev mmcblk0, sector 1234 op 0x1:(WRITE) flags 0x0","__REALTIME_TIMESTAMP":"` +
		strconv.FormatInt(boot.Add(101*time.Second).UnixMicro(), 10) + `"}`})
	evs := parseKernelRecords(append(recs, journal...))
	// mmc0 (host) and mmcblk0 (card) at minute 1 form one group, ext4 warning at minute 3 another.
	if len(evs) != 2 {
		t.Fatalf("expected 2 events, got %+v", evs)
	}
	if evs[0].Kind != protocol.EventDiskError || !strings.Contains(evs[0].Message, "+2 similar") {
		t.Fatalf("grouping: %+v", evs[0])
	}
	if evs[1].Device != "mmcblk0p2" {
		t.Fatalf("ext4 warning: %+v", evs[1])
	}
}

func TestMMCDisks(t *testing.T) {
	root := t.TempDir()
	write := func(p, v string) {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), []byte(v+"\n"), 0o644)
	}
	write("mmcblk0/size", "62333952")
	write("mmcblk0/device/type", "SD")
	write("mmcblk0/device/name", "SN64G")
	write("mmcblk0/device/serial", "0x1234abcd")
	write("mmcblk1/size", "30535680")
	write("mmcblk1/device/type", "MMC")
	write("mmcblk1/device/name", "8GTF4R")
	write("mmcblk1/device/life_time", "0x09 0x0a")
	write("mmcblk1/device/pre_eol_info", "0x03")
	write("mmcblk1boot0/size", "8192")
	disks := mmcDisks(root, "/dev/mmcblk0")
	if len(disks) != 2 {
		t.Fatalf("expected 2 disks, got %+v", disks)
	}
	sd, emmc := disks[0], disks[1]
	if !sd.System || sd.Bus != "SD" || sd.SizeBytes != 62333952*512 || sd.Serial != "SN64G-0x1234abcd" || sd.HealthPassed != nil {
		t.Fatalf("sd: %+v", sd)
	}
	if emmc.Bus != "eMMC" || emmc.PercentUsed == nil || *emmc.PercentUsed != 100 || emmc.HealthPassed == nil || *emmc.HealthPassed {
		t.Fatalf("emmc: %+v", emmc)
	}
}
