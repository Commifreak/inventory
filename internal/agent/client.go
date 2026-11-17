package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/commifreak/inventory/internal/protocol"
)

// ErrUnauthorized means the server does not accept the credential.
var ErrUnauthorized = errors.New("server rejected the device credential")

// Client talks to the server.
type Client struct {
	BaseURL    string
	Credential string
	HTTP       *http.Client
}

// NewClient creates a client that uses the system proxy (see proxy.go).
func NewClient(baseURL, credential string) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = systemProxy
	tr.ResponseHeaderTimeout = 2 * time.Minute
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Credential: credential, HTTP: &http.Client{Transport: tr, Timeout: 15 * time.Minute}}
}

func (c *Client) userAgent() string {
	return fmt.Sprintf("inventory-agent/%s (%s; %s)", Version, runtime.GOOS, runtime.GOARCH)
}

func (c *Client) do(ctx context.Context, method, path string, body any, gz bool, out any) error {
	var rd io.Reader
	var encoding string
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		if gz && len(b) > 4096 {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(b)
			_ = zw.Close()
			b = buf.Bytes()
			encoding = "gzip"
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.userAgent())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	if c.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.Credential)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(msg, &e) == nil && e.Error != "" {
			return fmt.Errorf("server returned %d: %s", resp.StatusCode, e.Error)
		}
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
	}
	return nil
}

// Enroll registers the device.
func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (*protocol.EnrollResponse, error) {
	var resp protocol.EnrollResponse
	if err := c.do(ctx, http.MethodPost, protocol.APIPrefix+"/enroll", req, false, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Checkin sends the heartbeat.
func (c *Client) Checkin(ctx context.Context, req protocol.CheckinRequest) (*protocol.CheckinResponse, error) {
	var resp protocol.CheckinResponse
	if err := c.do(ctx, http.MethodPost, protocol.APIPrefix+"/checkin", req, false, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Report uploads collector output.
func (c *Client) Report(ctx context.Context, rep protocol.Report) error {
	return c.do(ctx, http.MethodPost, protocol.APIPrefix+"/report", rep, true, nil)
}

// Ping checks that the server is reachable.
func (c *Client) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, protocol.APIPrefix+"/ping", nil, false, nil)
}

// Download fetches url (absolute or server relative) into path.
func (c *Client) Download(ctx context.Context, url, path string, maxSize int64) error {
	if strings.HasPrefix(url, "/") {
		url = c.BaseURL + url
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.userAgent())
	if c.Credential != "" && strings.HasPrefix(url, c.BaseURL+"/") {
		req.Header.Set("Authorization", "Bearer "+c.Credential)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: server returned %d", resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxSize {
		return errors.New("download larger than announced")
	}
	return nil
}
