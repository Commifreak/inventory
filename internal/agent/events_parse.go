package agent

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/commifreak/inventory/internal/protocol"
)

type evtXML struct {
	Events []struct {
		System struct {
			Provider struct {
				Name string `xml:"Name,attr"`
			} `xml:"Provider"`
			EventID     int `xml:"EventID"`
			TimeCreated struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
			EventRecordID int64 `xml:"EventRecordID"`
		} `xml:"System"`
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"EventData>Data"`
		Message string `xml:"RenderingInfo>Message"`
	} `xml:"Event"`
}

// ParseWindowsEvents converts wevtutil RenderedXml output.
func ParseWindowsEvents(out string) ([]protocol.CriticalEvent, error) {
	var x evtXML
	dec := xml.NewDecoder(strings.NewReader("<Events>" + out + "</Events>"))
	dec.Strict = false
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := dec.Decode(&x); err != nil {
		return nil, fmt.Errorf("parse events: %w", err)
	}
	var evs []protocol.CriticalEvent
	for _, e := range x.Events {
		t, _ := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime)
		kind := protocol.EventDiskError
		prov := e.System.Provider.Name
		if e.System.EventID == 1001 && (prov == "BugCheck" || strings.Contains(prov, "SystemErrorReporting")) {
			kind = protocol.EventBluescreen
		}
		msg := strings.TrimSpace(e.Message)
		if msg == "" {
			var parts []string
			for _, d := range e.Data {
				if d.Value != "" {
					parts = append(parts, d.Value)
				}
			}
			msg = strings.Join(parts, " | ")
		}
		dev := ""
		if kind == protocol.EventDiskError {
			for _, d := range e.Data {
				if strings.HasPrefix(d.Value, `\Device\Harddisk`) {
					dev = d.Value
				}
			}
		}
		evs = append(evs, protocol.CriticalEvent{Kind: kind, Time: t, Source: prov, EventID: e.System.EventID, Device: dev,
			Message: truncateStr(msg, 1000), Key: "evt|" + strconv.FormatInt(e.System.EventRecordID, 10)})
	}
	return evs, nil
}

// decodeUTF16 decodes little endian UTF-16 (with or without BOM). Input that
// is not UTF-16 is returned unchanged.
func decodeUTF16(b []byte) string {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		b = b[2:]
	} else if len(b) < 2 || b[1] != 0 {
		return string(b)
	}
	if len(b)%2 == 1 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}
