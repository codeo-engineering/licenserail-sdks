package licenserail

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Options configure a Client. ServerURL, Vendor, Product and PublicKeyPEM are required.
type Options struct {
	// Vendor is your organization ID from the dashboard (ten_...; part of every device identity).
	Vendor string
	ServerURL        string
	Product          string
	PublicKeyPEM     string
	AppVersion       string
	StorageDir       string
	RefreshOnStartup bool
	Timeout          time.Duration
	MachineName      string
	// Fingerprint overrides device fingerprinting (tests, custom ids).
	Fingerprint func() Fingerprint
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Result of an activation or deactivation.
type Result struct {
	Success   bool
	ErrorCode string
	Message   string
}

// CheckResult is the current state.
type CheckResult struct {
	Status  Status
	License *Payload
}

// Valid reports whether the license may be used.
func (r CheckResult) Valid() bool { return r.Status == Valid }

// Client licenses a vendor's app. It needs only the public key; never ship an API key.
type Client struct {
	opts  Options
	key   *ecdsa.PublicKey
	http  *http.Client
	dir   string
	once  sync.Once
	fp    Fingerprint
	mu    sync.Mutex
	stop  chan struct{}
	// LastServerMessage explains why a license was removed by the server.
	LastServerMessage string
}

// NewClient validates the options and loads the public key.
func NewClient(o Options) (*Client, error) {
	if o.ServerURL == "" || o.Vendor == "" || o.Product == "" || o.PublicKeyPEM == "" {
		return nil, errors.New("licenserail: ServerURL, Vendor, Product and PublicKeyPEM are required")
	}
	key, err := ParsePublicKey(o.PublicKeyPEM)
	if err != nil {
		return nil, err
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	dir := o.StorageDir
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			base = os.TempDir()
		}
		dir = filepath.Join(base, "licenserail", o.Product)
	}
	return &Client{opts: o, key: key, http: &http.Client{Timeout: o.Timeout}, dir: dir}, nil
}

func (c *Client) now() time.Time {
	if c.opts.Now != nil {
		return c.opts.Now()
	}
	return time.Now()
}

func (c *Client) fingerprint() Fingerprint {
	c.once.Do(func() {
		if c.opts.Fingerprint != nil {
			c.fp = c.opts.Fingerprint()
		} else {
			c.fp = CollectFingerprint(c.opts.Vendor, c.opts.Product)
		}
	})
	return c.fp
}

// License returns the current license payload, or nil.
func (c *Client) License() *Payload { return VerifyToken(c.read("license.lic"), c.key) }

// EvaluateLocal evaluates offline only.
func (c *Client) EvaluateLocal() CheckResult {
	token := c.read("license.lic")
	if token == "" {
		return CheckResult{Status: Missing}
	}
	p := VerifyToken(token, c.key)
	last := decodeHistory(c.read("license.seen"), c.opts.Vendor, c.opts.Product, c.fingerprint())
	now := c.now()
	s := Evaluate(p, c.opts.Product, c.fingerprint(), now, last)
	if (s == Valid || s == Expired || s == OfflineTooLong) && (last == nil || now.After(*last)) {
		c.write("license.seen", encodeHistory(now, c.opts.Vendor, c.opts.Product, c.fingerprint()))
	}
	return CheckResult{Status: s, License: p}
}

// Check evaluates offline and refreshes online when due or when only the server can clear the state. Call it on startup.
func (c *Client) Check(ctx context.Context) CheckResult {
	r := c.EvaluateLocal()
	due := r.Valid() && (c.opts.RefreshOnStartup || !c.now().Before(r.License.RefreshAfter))
	switch r.Status {
	case Expired, Suspended, OfflineTooLong, ClockTampered, Unverified:
		due = true
	}
	if due {
		var anomalies []string
		if r.Status == ClockTampered {
			anomalies = []string{"clock_rollback"}
		} else if r.Status == Unverified {
			anomalies = []string{"history_missing"}
		}
		_ = c.Refresh(ctx, anomalies)
		r = c.EvaluateLocal()
	}
	if r.License != nil && r.License.Test {
		fmt.Fprintln(os.Stderr, "[licenserail] Test license: not for production use.")
	}
	return r
}

// Activate activates licenseKey on this device (a floating license is checked out and kept alive with heartbeats).
func (c *Client) Activate(ctx context.Context, licenseKey, machineName string) Result {
	licenseKey = strings.TrimSpace(licenseKey)
	if licenseKey == "" {
		return Result{ErrorCode: "bad_request", Message: "Enter the license key."}
	}
	if fp := c.fingerprint(); !fp.Matches(fp) { // would only use up a seat
		return Result{ErrorCode: "device_not_identified", Message: "This device can't be identified, so a license can't be activated on it."}
	}
	if machineName == "" {
		machineName = c.opts.MachineName
	}
	if machineName == "" {
		machineName, _ = os.Hostname()
	}
	body := map[string]interface{}{"licenseKey": licenseKey, "product": c.opts.Product, "fingerprint": c.fingerprint(),
		"machineName": machineName, "appVersion": c.opts.AppVersion}
	resp, err := c.post(ctx, "/api/client/v2/activate", body)
	if err == nil && !resp.ok && resp.Code == "bad_request" && strings.Contains(strings.ToLower(resp.Message), "floating") {
		resp, err = c.post(ctx, "/api/client/v2/floating/checkout", body)
	}
	if err != nil {
		return Result{ErrorCode: "network", Message: "Could not connect to the license server."}
	}
	if !resp.ok {
		return Result{ErrorCode: resp.Code, Message: resp.Message}
	}
	if !c.saveIfValid(resp.Token) {
		return Result{ErrorCode: "invalid_token", Message: "The server returned an invalid license."}
	}
	r := c.EvaluateLocal()
	if r.License != nil && r.License.Floating {
		c.startHeartbeat()
	}
	if !r.Valid() {
		return Result{ErrorCode: string(r.Status), Message: string(r.Status)}
	}
	return Result{Success: true, Message: "The license has been activated."}
}

// Deactivate removes the license from this device and frees its seat (floating: releases the lease).
func (c *Client) Deactivate(ctx context.Context) Result {
	c.stopHeartbeat()
	token := c.read("license.lic")
	if token == "" {
		return Result{Success: true, Message: "There is no license on this device."}
	}
	path := "/api/client/v2/deactivate"
	if p := VerifyToken(token, c.key); p != nil && p.Floating {
		path = "/api/client/v2/floating/release"
	}
	resp, err := c.post(ctx, path, map[string]interface{}{"token": token, "fingerprint": c.fingerprint()})
	if err != nil {
		return Result{ErrorCode: "network", Message: "Removing the license needs an internet connection."}
	}
	if !resp.ok && !RevokingCodes[resp.Code] {
		return Result{ErrorCode: resp.Code, Message: resp.Message}
	}
	c.remove("license.lic")
	if !resp.ok && resp.Code == "wrong_machine" {
		return Result{ErrorCode: resp.Code, Message: resp.Message}
	}
	return Result{Success: true, Message: "The license has been removed from this device."}
}

// Refresh asks the server for a fresh token now (floating licenses: a heartbeat).
func (c *Client) Refresh(ctx context.Context, anomalies []string) error {
	token := c.read("license.lic")
	if token == "" {
		return nil
	}
	path := "/api/client/v2/refresh"
	if p := VerifyToken(token, c.key); p != nil && p.Floating {
		path = "/api/client/v2/floating/heartbeat"
	}
	resp, err := c.post(ctx, path, map[string]interface{}{"token": token, "fingerprint": c.fingerprint(),
		"appVersion": c.opts.AppVersion, "anomalies": anomalies})
	if err != nil {
		return err
	}
	if resp.ok {
		c.saveIfValid(resp.Token)
	} else if RevokingCodes[resp.Code] || resp.Code == "lease_expired" {
		c.remove("license.lic")
		c.LastServerMessage = resp.Message
	}
	return nil
}

func (c *Client) startHeartbeat() {
	c.stopHeartbeat()
	p := c.License()
	if p == nil || !p.Floating {
		return
	}
	interval := p.OfflineUntil.Sub(p.IssuedAt) / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	c.mu.Lock()
	c.stop = make(chan struct{})
	stop := c.stop
	c.mu.Unlock()
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = c.Refresh(context.Background(), nil)
			case <-stop:
				return
			}
		}
	}()
}

func (c *Client) stopHeartbeat() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stop != nil {
		close(c.stop)
		c.stop = nil
	}
}

type serverResponse struct {
	ok      bool
	Token   string `json:"token"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *Client) post(ctx context.Context, path string, body interface{}) (serverResponse, error) {
	data, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.opts.ServerURL, "/")+path, bytes.NewReader(data))
	if err != nil {
		return serverResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return serverResponse{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var r serverResponse
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &r); err != nil {
			return serverResponse{}, err
		}
	}
	r.ok = res.StatusCode < 400
	if !r.ok && r.Message == "" {
		r.Message = fmt.Sprintf("Server error (%d).", res.StatusCode)
	}
	return r, nil
}

func (c *Client) saveIfValid(token string) bool {
	p := VerifyToken(token, c.key)
	if p == nil || !strings.EqualFold(p.Product, c.opts.Product) {
		return false
	}
	c.write("license.lic", token)
	c.write("license.seen", encodeHistory(c.now(), c.opts.Vendor, c.opts.Product, c.fingerprint()))
	return true
}

func (c *Client) read(name string) string {
	b, err := os.ReadFile(filepath.Join(c.dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (c *Client) write(name, value string) {
	_ = os.MkdirAll(c.dir, 0o700)
	_ = os.WriteFile(filepath.Join(c.dir, name), []byte(value), 0o600)
}

func (c *Client) remove(name string) { _ = os.Remove(filepath.Join(c.dir, name)) }
