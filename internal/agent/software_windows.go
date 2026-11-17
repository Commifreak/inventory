package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/commifreak/inventory/internal/protocol"
)

// userHives returns loaded user registry hives (SID -> name).
func userHives() map[string]string {
	out := map[string]string{}
	names, err := registry.USERS.ReadSubKeyNames(-1)
	if err != nil {
		return out
	}
	for _, sid := range names {
		if (strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")) && !strings.HasSuffix(sid, "_Classes") {
			out[sid] = sidName(sid)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// software (Uninstall registry keys; Win32_Product is avoided on purpose:
// querying it triggers MSI consistency checks/repairs)
// ---------------------------------------------------------------------------

func collectSoftwareWindows(ctx context.Context, _ *State) (any, []string, error) {
	var items []protocol.SoftwareItem
	seen := map[string]bool{}
	const path = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	read := func(root registry.Key, access uint32, scope, arch string) {
		k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|access)
		if err != nil {
			return
		}
		defer k.Close()
		subs, _ := k.ReadSubKeyNames(-1)
		for _, sub := range subs {
			sk, err := registry.OpenKey(k, sub, registry.QUERY_VALUE|access)
			if err != nil {
				continue
			}
			get := func(n string) string { v, _, _ := sk.GetStringValue(n); return strings.TrimSpace(v) }
			getInt := func(n string) uint64 { v, _, _ := sk.GetIntegerValue(n); return v }
			name := get("DisplayName")
			skip := name == "" || getInt("SystemComponent") == 1 || get("ParentKeyName") != "" ||
				get("ReleaseType") == "Update" || get("ReleaseType") == "Hotfix" || get("ReleaseType") == "Security Update"
			if !skip {
				it := protocol.SoftwareItem{Name: name, Version: get("DisplayVersion"), Publisher: get("Publisher"), Source: "registry", Scope: scope, Arch: arch}
				if d := get("InstallDate"); len(d) == 8 {
					it.InstallDate = d[:4] + "-" + d[4:6] + "-" + d[6:]
				}
				key := it.Name + "|" + it.Version + "|" + scope
				if !seen[key] {
					seen[key] = true
					items = append(items, it)
				}
			}
			sk.Close()
		}
	}
	read(registry.LOCAL_MACHINE, registry.WOW64_64KEY, "machine", "x64")
	read(registry.LOCAL_MACHINE, registry.WOW64_32KEY, "machine", "x86")
	for sid, name := range userHives() {
		k, err := registry.OpenKey(registry.USERS, sid, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		read(k, 0, "user:"+name, "")
		k.Close()
	}
	if runtime.GOARCH == "arm64" {
		for i := range items {
			if items[i].Arch == "x64" {
				items[i].Arch = "arm64/x64"
			}
		}
	}
	return protocol.SoftwareData{Items: items}, nil, nil
}

// ---------------------------------------------------------------------------
// autostart
// ---------------------------------------------------------------------------

func collectAutostartWindows(ctx context.Context, _ *State) (any, []string, error) {
	var items []protocol.AutostartItem
	var warns []string

	// Run keys with StartupApproved state.
	runKeys := []struct{ path, approved string }{
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`},
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, ""},
	}
	readRun := func(root registry.Key, rootName string, access uint32, scope string, approvedPath string) {
		for _, rk := range runKeys {
			k, err := registry.OpenKey(root, rk.path, registry.QUERY_VALUE|access)
			if err != nil {
				continue
			}
			names, _ := k.ReadValueNames(-1)
			ap := approvedPath
			if rk.approved == "" {
				ap = ""
			}
			for _, n := range names {
				cmd, _, err := k.GetStringValue(n)
				if err != nil {
					continue
				}
				items = append(items, protocol.AutostartItem{Name: n, Command: cmd, Location: rootName + `\` + rk.path, Scope: scope,
					Enabled: startupApproved(root, ap, n)})
			}
			k.Close()
		}
	}
	readRun(registry.LOCAL_MACHINE, "HKLM", registry.WOW64_64KEY, "machine", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`)
	readRun(registry.LOCAL_MACHINE, "HKLM (32-bit)", registry.WOW64_32KEY, "machine", `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32`)
	for sid, name := range userHives() {
		k, err := registry.OpenKey(registry.USERS, sid, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		readRun(k, "HKCU", 0, "user:"+name, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`)
		k.Close()
	}

	// Startup folders.
	folders := map[string]string{filepath.Join(envDir("ProgramData", `C:\ProgramData`), `Microsoft\Windows\Start Menu\Programs\StartUp`): "machine"}
	users, _ := filepath.Glob(filepath.Join(envDir("SystemDrive", "C:")+`\`, `Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
	for _, u := range users {
		folders[u] = "user:" + strings.Split(strings.TrimPrefix(u, envDir("SystemDrive", "C:")+`\Users\`), `\`)[0]
	}
	for dir, scope := range folders {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			items = append(items, protocol.AutostartItem{Name: e.Name(), Command: filepath.Join(dir, e.Name()), Location: "Startup folder", Scope: scope, Enabled: true})
		}
	}

	// Scheduled tasks with boot/logon triggers.
	tasks, err := scheduledTasks(ctx)
	if err != nil {
		warns = append(warns, "scheduled tasks: "+err.Error())
	}
	items = append(items, tasks...)

	// Automatically started services.
	svcs, err := autoServices()
	if err != nil {
		warns = append(warns, "services: "+err.Error())
	}
	items = append(items, svcs...)
	return protocol.AutostartData{Items: items}, warns, nil
}

// startupApproved checks the Task Manager "disabled" flag (first byte odd = disabled).
func startupApproved(root registry.Key, path, name string) bool {
	if path == "" {
		return true
	}
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return true
	}
	defer k.Close()
	v, _, err := k.GetBinaryValue(name)
	if err != nil || len(v) == 0 {
		return true
	}
	return v[0]%2 == 0
}

func autoServices() ([]protocol.AutostartItem, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	winDir := strings.ToLower(envDir("SystemRoot", `C:\Windows`))
	var out []protocol.AutostartItem
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		cfg, err := s.Config()
		s.Close()
		if err != nil || cfg.StartType != mgr.StartAutomatic || cfg.ServiceType&0x30 == 0 { // win32 services only
			continue
		}
		bin := cfg.BinaryPathName
		low := strings.ToLower(strings.Trim(bin, `"`))
		vendor := strings.HasPrefix(low, winDir) || strings.HasPrefix(low, `%systemroot%`) || strings.HasPrefix(low, `system32\`)
		display := cfg.DisplayName
		if display == "" {
			display = n
		}
		out = append(out, protocol.AutostartItem{Name: display + " (" + n + ")", Command: bin, Location: "Service", Scope: "machine", Enabled: true, Vendor: vendor})
	}
	return out, nil
}

// scheduledTasks lists tasks with boot or logon triggers via the Task Scheduler COM API.
func scheduledTasks(ctx context.Context) ([]protocol.AutostartItem, error) {
	type res struct {
		items []protocol.AutostartItem
		err   error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		items, err := scheduledTasksCOM()
		ch <- res{items, err}
	}()
	select {
	case r := <-ch:
		return r.items, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func scheduledTasksCOM() ([]protocol.AutostartItem, error) {
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		if oe, ok := err.(*ole.OleError); !ok || oe.Code() != 1 {
			return nil, err
		}
	}
	defer ole.CoUninitialize()
	svc, err := createObject("Schedule.Service")
	if err != nil {
		return nil, err
	}
	defer svc.Release()
	if _, err := oleutil.CallMethod(svc, "Connect"); err != nil {
		return nil, fmt.Errorf("connect: %s", comErr(err))
	}
	rv, err := oleutil.CallMethod(svc, "GetFolder", `\`)
	if err != nil {
		return nil, fmt.Errorf("GetFolder: %s", comErr(err))
	}
	root := rv.ToIDispatch()
	defer root.Release()
	var out []protocol.AutostartItem
	var walk func(f *ole.IDispatch, depth int)
	walk = func(f *ole.IDispatch, depth int) {
		if depth > 10 {
			return
		}
		folderPath := propString(f, "Path")
		vendor := strings.HasPrefix(folderPath, `\Microsoft`)
		if tv, err := oleutil.CallMethod(f, "GetTasks", 1); err == nil { // include hidden
			forEach(tv.ToIDispatch(), func(t *ole.IDispatch) {
				defer t.Release()
				defv, err := getProp(t, "Definition")
				if err != nil {
					return
				}
				def := defv.ToIDispatch()
				defer defv.Clear()
				trig := ""
				if trv, err := getProp(def, "Triggers"); err == nil {
					forEach(trv.ToIDispatch(), func(tr *ole.IDispatch) {
						switch propInt(tr, "Type") {
						case 8:
							trig = "at boot"
						case 9:
							if trig == "" {
								trig = "at logon"
							}
						}
						tr.Release()
					})
					trv.Clear()
				}
				if trig == "" {
					return
				}
				var cmds []string
				if av, err := getProp(def, "Actions"); err == nil {
					forEach(av.ToIDispatch(), func(a *ole.IDispatch) {
						if propInt(a, "Type") == 0 {
							cmds = append(cmds, strings.TrimSpace(propString(a, "Path")+" "+propString(a, "Arguments")))
						}
						a.Release()
					})
					av.Clear()
				}
				out = append(out, protocol.AutostartItem{Name: propString(t, "Path"), Command: strings.Join(cmds, "; "),
					Location: "Scheduled task (" + trig + ")", Scope: "machine", Enabled: propBool(t, "Enabled"), Vendor: vendor})
			})
			tv.Clear()
		}
		if fv, err := oleutil.CallMethod(f, "GetFolders", 0); err == nil {
			forEach(fv.ToIDispatch(), func(sub *ole.IDispatch) {
				walk(sub, depth+1)
				sub.Release()
			})
			fv.Clear()
		}
	}
	walk(root, 0)
	return out, nil
}

// ---------------------------------------------------------------------------
// events (System event log)
// ---------------------------------------------------------------------------

// Event selection: bug checks and disk/file system errors.
const evtQuery = `*[System[(` +
	`(Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting' or @Name='BugCheck'] and EventID=1001) or ` +
	`(Provider[@Name='disk'] and (EventID=7 or EventID=11 or EventID=51 or EventID=52 or EventID=153)) or ` +
	`(Provider[@Name='Ntfs' or @Name='Microsoft-Windows-Ntfs'] and EventID=55) or ` +
	`(Provider[@Name='stornvme'] and (EventID=11 or EventID=129)) or ` +
	`(Provider[@Name='storahci'] and EventID=129)` +
	`) and TimeCreated[@SystemTime>='%s']]]`

func collectEventsWindows(ctx context.Context, st *State) (any, []string, error) {
	since := st.EventsSince
	if since.IsZero() || time.Since(since) > 31*24*time.Hour {
		since = time.Now().Add(-30 * 24 * time.Hour)
	}
	q := fmt.Sprintf(evtQuery, since.UTC().Format("2006-01-02T15:04:05.000Z"))
	// /uni:true makes wevtutil emit UTF-16, which survives any console code page.
	out, err := runCmd(ctx, "wevtutil", "qe", "System", "/q:"+q, "/f:RenderedXml", "/c:500", "/rd:true", "/uni:true")
	if err != nil {
		return nil, nil, err
	}
	events, err := ParseWindowsEvents(decodeUTF16([]byte(out)))
	if err != nil {
		return nil, nil, err
	}
	return protocol.EventsData{Since: since, Events: events}, nil, nil
}
