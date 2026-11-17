package agent

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/commifreak/inventory/internal/protocol"
)

// collectUpdatesWindows queries the Windows Update Agent. Searching never
// downloads or installs anything.
func collectUpdatesWindows(ctx context.Context, _ *State) (any, []string, error) {
	type result struct {
		u     protocol.UpdatesData
		warns []string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		// COM objects are bound to the OS thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		u, w, err := windowsUpdateCOM()
		ch <- result{u, w, err}
	}()
	var r result
	select {
	case r = <-ch:
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("Windows Update query timed out")
	}
	if r.err != nil {
		return nil, r.warns, r.err
	}
	u := r.u
	// Registry based facts.
	if regKeyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		u.RebootRequired = true
		u.RebootReasons = append(u.RebootReasons, "Windows Update")
	}
	if regKeyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		u.RebootRequired = true
		u.RebootReasons = append(u.RebootReasons, "Component Based Servicing")
	}
	u.RebootReasons = uniqueStrings(u.RebootReasons)
	const pol = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
	if use, _ := regDWord(registry.LOCAL_MACHINE, pol+`\AU`, "UseWUServer"); use == 1 {
		u.Source = "WSUS: " + regString(registry.LOCAL_MACHINE, pol, "WUServer")
	} else {
		u.Source = "Windows Update"
	}
	auto := true
	info := ""
	if v, _ := regDWord(registry.LOCAL_MACHINE, pol+`\AU`, "NoAutoUpdate"); v == 1 {
		auto, info = false, "disabled by policy (NoAutoUpdate)"
	}
	u.Services = windowsServices([]string{"wuauserv", "UsoSvc", "BITS", "TrustedInstaller"})
	for _, s := range u.Services {
		if s.Name == "wuauserv" && s.StartType == "disabled" {
			auto, info = false, "Windows Update service disabled"
		}
	}
	u.AutoUpdates, u.AutoUpdatesInfo = boolPtr(auto), info
	return u, r.warns, nil
}

func regKeyExists(path string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

func windowsServices(names []string) []protocol.ServiceState {
	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()
	states := map[uint32]string{1: "stopped", 2: "start pending", 3: "stop pending", 4: "running", 5: "continue pending", 6: "pause pending", 7: "paused"}
	starts := map[uint32]string{0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
	var out []protocol.ServiceState
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		st := protocol.ServiceState{Name: n}
		if cfg, err := s.Config(); err == nil {
			st.Display = cfg.DisplayName
			st.StartType = starts[cfg.StartType]
			if cfg.DelayedAutoStart && cfg.StartType == 2 {
				st.StartType = "automatic (delayed)"
			}
		}
		if q, err := s.Query(); err == nil {
			st.State = states[uint32(q.State)]
		}
		s.Close()
		out = append(out, st)
	}
	return out
}

// ---------------------------------------------------------------------------
// COM: Windows Update Agent API
// ---------------------------------------------------------------------------

func comErr(err error) string {
	var oe *ole.OleError
	if errors.As(err, &oe) {
		return fmt.Sprintf("0x%08X %s", uint32(oe.Code()), strings.TrimSpace(oe.String()))
	}
	return err.Error()
}

func createObject(progID string) (*ole.IDispatch, error) {
	unk, err := oleutil.CreateObject(progID)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", progID, comErr(err))
	}
	defer unk.Release()
	return unk.QueryInterface(ole.IID_IDispatch)
}

func getProp(d *ole.IDispatch, name string, args ...any) (*ole.VARIANT, error) {
	return oleutil.GetProperty(d, name, args...)
}

func propString(d *ole.IDispatch, name string) string {
	v, err := getProp(d, name)
	if err != nil {
		return ""
	}
	defer v.Clear()
	if s, ok := v.Value().(string); ok {
		return s
	}
	return ""
}

func propInt(d *ole.IDispatch, name string) int64 {
	v, err := getProp(d, name)
	if err != nil {
		return 0
	}
	defer v.Clear()
	switch n := v.Value().(type) {
	case int32:
		return int64(n)
	case int64:
		return n
	case uint32:
		return int64(n)
	case int16:
		return int64(n)
	case uint8:
		return int64(n)
	case float64:
		return int64(n)
	case int:
		return int64(n)
	}
	return 0
}

func propBool(d *ole.IDispatch, name string) bool {
	v, err := getProp(d, name)
	if err != nil {
		return false
	}
	defer v.Clear()
	b, _ := v.Value().(bool)
	return b
}

func propTime(d *ole.IDispatch, name string) time.Time {
	v, err := getProp(d, name)
	if err != nil {
		return time.Time{}
	}
	defer v.Clear()
	if t, ok := v.Value().(time.Time); ok && t.Year() > 1990 {
		return t
	}
	return time.Time{}
}

// forEach iterates an IUpdateCollection-like object (Count / Item(i)).
func forEach(coll *ole.IDispatch, fn func(item *ole.IDispatch)) {
	n := propInt(coll, "Count")
	for i := int64(0); i < n; i++ {
		v, err := getProp(coll, "Item", i)
		if err != nil {
			continue
		}
		item := v.ToIDispatch()
		if item != nil {
			fn(item)
		}
		v.Clear()
	}
}

func windowsUpdateCOM() (protocol.UpdatesData, []string, error) {
	u := protocol.UpdatesData{Manager: "Windows Update"}
	var warns []string
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		var oe *ole.OleError
		// S_FALSE (already initialised) is fine.
		if !errors.As(err, &oe) || oe.Code() != 1 {
			return u, nil, fmt.Errorf("CoInitializeEx: %s", comErr(err))
		}
	}
	defer ole.CoUninitialize()

	session, err := createObject("Microsoft.Update.Session")
	if err != nil {
		return u, nil, err
	}
	defer session.Release()
	_, _ = oleutil.PutProperty(session, "ClientApplicationID", "Inventory Agent")
	sv, err := oleutil.CallMethod(session, "CreateUpdateSearcher")
	if err != nil {
		return u, nil, fmt.Errorf("CreateUpdateSearcher: %s", comErr(err))
	}
	searcher := sv.ToIDispatch()
	defer searcher.Release()

	// Pending updates.
	rv, err := oleutil.CallMethod(searcher, "Search", "IsInstalled=0 and IsHidden=0")
	if err != nil {
		u.SearchError = comErr(err)
	} else {
		res := rv.ToIDispatch()
		updates, err := getProp(res, "Updates")
		if err == nil {
			forEach(updates.ToIDispatch(), func(up *ole.IDispatch) {
				p := protocol.PendingUpdate{Title: propString(up, "Title"), Severity: propString(up, "MsrcSeverity"),
					Released: propTime(up, "LastDeploymentChangeTime"), Size: uint64(propInt(up, "MaxDownloadSize"))}
				if kbs, err := getProp(up, "KBArticleIDs"); err == nil {
					var ids []string
					kc := kbs.ToIDispatch()
					n := propInt(kc, "Count")
					for i := int64(0); i < n; i++ {
						if v, err := getProp(kc, "Item", i); err == nil {
							if s, ok := v.Value().(string); ok {
								ids = append(ids, "KB"+s)
							}
							v.Clear()
						}
					}
					p.KB = strings.Join(ids, ", ")
					kbs.Clear()
				}
				if cats, err := getProp(up, "Categories"); err == nil {
					var names []string
					forEach(cats.ToIDispatch(), func(c *ole.IDispatch) { names = append(names, propString(c, "Name")) })
					cats.Clear()
					p.Category = strings.Join(names, ", ")
					for _, n := range names {
						if n == "Security Updates" || n == "Critical Updates" {
							p.Security = true
						}
					}
				}
				if p.Severity == "Critical" || p.Severity == "Important" {
					p.Security = true
				}
				u.Pending = append(u.Pending, p)
				up.Release()
			})
			updates.Clear()
		}
		res.Release()
	}
	u.PendingCount = len(u.Pending)
	for _, p := range u.Pending {
		if p.Security {
			u.SecurityCount++
		}
	}

	// History.
	total := propIntCall(searcher, "GetTotalHistoryCount")
	if total > 0 {
		n := min(total, 100)
		hv, err := oleutil.CallMethod(searcher, "QueryHistory", 0, n)
		if err != nil {
			warns = append(warns, "update history: "+comErr(err))
		} else {
			results := map[int64]string{0: "NotStarted", 1: "InProgress", 2: "Succeeded", 3: "SucceededWithErrors", 4: "Failed", 5: "Aborted"}
			seenIntel := false
			forEach(hv.ToIDispatch(), func(e *ole.IDispatch) {
				defer e.Release()
				title := propString(e, "Title")
				if title == "" {
					return
				}
				// Defender intelligence updates arrive several times a day: keep the latest only.
				if strings.Contains(title, "Security Intelligence Update") || strings.Contains(title, "KB2267602") {
					if seenIntel {
						return
					}
					seenIntel = true
				}
				h := protocol.UpdateHistoryEntry{Title: title, Date: propTime(e, "Date"), Result: results[propInt(e, "ResultCode")]}
				if hr := propInt(e, "HResult"); hr != 0 {
					h.HResult = fmt.Sprintf("0x%08X", uint32(hr))
				}
				switch propInt(e, "Operation") {
				case 1:
					h.Operation = "Installation"
				case 2:
					h.Operation = "Uninstallation"
				}
				u.History = append(u.History, h)
			})
			hv.Clear()
		}
	}

	// Last search/installation and reboot state.
	if au, err := createObject("Microsoft.Update.AutoUpdate"); err == nil {
		if rv, err := getProp(au, "Results"); err == nil {
			r := rv.ToIDispatch()
			u.LastSearch = propTime(r, "LastSearchSuccessDate")
			u.LastInstall = propTime(r, "LastInstallationSuccessDate")
			rv.Clear()
		}
		au.Release()
	}
	if si, err := createObject("Microsoft.Update.SystemInfo"); err == nil {
		if propBool(si, "RebootRequired") {
			u.RebootRequired = true
			u.RebootReasons = append(u.RebootReasons, "Windows Update")
		}
		si.Release()
	}
	if u.LastInstall.IsZero() {
		for _, h := range u.History {
			if h.Result == "Succeeded" && h.Date.After(u.LastInstall) {
				u.LastInstall = h.Date
			}
		}
	}
	return u, warns, nil
}

func propIntCall(d *ole.IDispatch, method string) int64 {
	v, err := oleutil.CallMethod(d, method)
	if err != nil {
		return 0
	}
	defer v.Clear()
	switch n := v.Value().(type) {
	case int32:
		return int64(n)
	case int64:
		return n
	}
	return 0
}
