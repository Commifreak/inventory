package agent

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/yusufpapurcu/wmi"

	"github.com/commifreak/inventory/internal/protocol"
)

const defenderNS = `root\Microsoft\Windows\Defender`

type msftMpThreatDetection struct {
	DetectionID                string
	ThreatID                   int64
	InitialDetectionTime       time.Time
	LastThreatStatusChangeTime time.Time
	ThreatStatusID             uint32
	Resources                  []string
	DomainUser                 string
	ProcessName                string
}

type msftMpThreat struct {
	ThreatID   int64
	ThreatName string
	SeverityID uint32
}

type msftMpPreference struct {
	ExclusionPath      []string
	ExclusionExtension []string
	ExclusionProcess   []string
	ExclusionIpAddress []string
}

// Defender threat status IDs (MSFT_MpThreatDetection.ThreatStatusID).
var defenderThreatStatus = map[uint32]string{0: "unknown", 1: "detected", 2: "cleaned", 3: "quarantined", 4: "removed", 5: "allowed",
	6: "blocked", 102: "quarantine failed", 103: "removal failed", 104: "allow failed", 105: "abandoned", 107: "block failed"}

var defenderSeverity = map[uint32]string{1: "low", 2: "moderate", 4: "high", 5: "severe"}

// defenderDetections returns Defender detections of the last 90 days.
func defenderDetections() ([]protocol.ThreatDetection, error) {
	var dets []msftMpThreatDetection
	if err := wmi.QueryNamespace("SELECT DetectionID, ThreatID, InitialDetectionTime, LastThreatStatusChangeTime, ThreatStatusID, Resources, DomainUser, ProcessName FROM MSFT_MpThreatDetection", &dets, defenderNS); err != nil {
		return nil, err
	}
	var threats []msftMpThreat
	_ = wmi.QueryNamespace("SELECT ThreatID, ThreatName, SeverityID FROM MSFT_MpThreat", &threats, defenderNS)
	byID := map[int64]msftMpThreat{}
	for _, t := range threats {
		byID[t.ThreatID] = t
	}
	cut := time.Now().AddDate(0, 0, -90)
	var out []protocol.ThreatDetection
	for _, d := range dets {
		if !d.InitialDetectionTime.IsZero() && d.InitialDetectionTime.Before(cut) {
			continue
		}
		t := byID[d.ThreatID]
		status := defenderThreatStatus[d.ThreatStatusID]
		if status == "" {
			status = "status " + strconv.Itoa(int(d.ThreatStatusID))
		}
		td := protocol.ThreatDetection{ID: d.DetectionID, Time: d.InitialDetectionTime, StatusTime: d.LastThreatStatusChangeTime,
			Threat: t.ThreatName, Severity: defenderSeverity[t.SeverityID], Status: status, User: d.DomainUser, Process: d.ProcessName,
			Resolved: d.ThreatStatusID >= 2 && d.ThreatStatusID <= 4 || d.ThreatStatusID == 6}
		if td.ID == "" {
			td.ID = fmt.Sprintf("%d-%d", d.ThreatID, d.InitialDetectionTime.Unix())
		}
		if td.Threat == "" {
			td.Threat = "threat " + strconv.FormatInt(d.ThreatID, 10)
		}
		for i, r := range d.Resources {
			if i == 10 {
				break
			}
			td.Resources = append(td.Resources, truncateStr(strings.TrimPrefix(r, "file:_"), 300))
		}
		out = append(out, td)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > 50 {
		out = out[:50]
	}
	return out, nil
}

// defenderExclusions returns the configured Defender exclusions (readable
// only with administrative rights, which the agent service has).
func defenderExclusions() ([]string, error) {
	var prefs []msftMpPreference
	if err := wmi.QueryNamespace("SELECT ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress FROM MSFT_MpPreference", &prefs, defenderNS); err != nil {
		return nil, err
	}
	out := []string{}
	if len(prefs) == 0 {
		return out, nil
	}
	add := func(prefix string, vals []string) {
		for _, v := range vals {
			v = strings.TrimSpace(v)
			// Without administrative rights Defender returns a placeholder.
			if v == "" || strings.HasPrefix(v, "N/A") {
				continue
			}
			out = append(out, prefix+v)
		}
	}
	p := prefs[0]
	add("path:", p.ExclusionPath)
	add("ext:", p.ExclusionExtension)
	add("process:", p.ExclusionProcess)
	add("ip:", p.ExclusionIpAddress)
	sort.Strings(out)
	return out, nil
}

type securityCenterAV struct {
	DisplayName            string
	ProductState           uint32
	PathToSignedProductExe string
}

// windowsAntivirus lists the antivirus products of the Security Center.
// productState: bits 12-15 = scanner on (0x1), bits 4-7 = signatures
// outdated (0x1).
func windowsAntivirus() ([]protocol.AntivirusProduct, error) {
	var avs []securityCenterAV
	if err := wmi.QueryNamespace("SELECT DisplayName, ProductState, PathToSignedProductExe FROM AntiVirusProduct", &avs, `root\SecurityCenter2`); err != nil {
		return nil, err
	}
	var out []protocol.AntivirusProduct
	for _, a := range avs {
		out = append(out, protocol.AntivirusProduct{Name: strings.TrimSpace(a.DisplayName),
			Enabled:  a.ProductState&0x1000 != 0,
			UpToDate: a.ProductState&0x10 == 0,
			Defender: strings.HasPrefix(strings.ToLower(a.PathToSignedProductExe), "windowsdefender://")})
	}
	return out, nil
}

// windowsFirewall returns the effective state of the three firewall
// profiles via HNetCfg.FwPolicy2 (includes group policy).
func windowsFirewall() ([]protocol.FirewallProfile, error) {
	type res struct {
		p   []protocol.FirewallProfile
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() {
			if r := recover(); r != nil {
				ch <- res{err: fmt.Errorf("firewall query panicked: %v", r)}
			}
		}()
		p, err := windowsFirewallCOM()
		ch <- res{p, err}
	}()
	select {
	case r := <-ch:
		return r.p, r.err
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("firewall query timed out")
	}
}

func windowsFirewallCOM() ([]protocol.FirewallProfile, error) {
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		if oe, ok := err.(*ole.OleError); !ok || oe.Code() != 1 {
			return nil, err
		}
	}
	defer ole.CoUninitialize()
	pol, err := createObject("HNetCfg.FwPolicy2")
	if err != nil {
		return nil, err
	}
	defer pol.Release()
	active := int64(0)
	if v, err := oleutil.GetProperty(pol, "CurrentProfileTypes"); err == nil {
		active = variantInt(v)
		_ = v.Clear()
	}
	var out []protocol.FirewallProfile
	for _, p := range []struct {
		name string
		typ  int64
	}{{"Domain", 1}, {"Private", 2}, {"Public", 4}} {
		v, err := oleutil.GetProperty(pol, "FirewallEnabled", p.typ)
		if err != nil {
			return nil, fmt.Errorf("FirewallEnabled(%s): %s", p.name, comErr(err))
		}
		enabled := v.Value() == true
		_ = v.Clear()
		out = append(out, protocol.FirewallProfile{Name: p.name, Enabled: enabled, Active: active&p.typ != 0})
	}
	return out, nil
}

func variantInt(v *ole.VARIANT) int64 {
	switch x := v.Value().(type) {
	case int32:
		return int64(x)
	case int64:
		return x
	case uint32:
		return int64(x)
	case int16:
		return int64(x)
	case uint16:
		return int64(x)
	case int:
		return int64(x)
	}
	return 0
}
