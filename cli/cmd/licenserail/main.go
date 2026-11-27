// licenserail: command-line interface for the LicenseRail API (working name; alias lr).
// Agent-friendly: --json gives stable machine output, every write sends an Idempotency-Key, and irreversible Live actions
// print an approval URL for a person instead of acting.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const version = "0.1.2"

// ---------------------------------------------------------------- config

type tenantRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
	Role string `json:"role"`
}

type config struct {
	APIURL      string      `json:"apiUrl"`
	Token       string      `json:"token,omitempty"`
	TokenIsKey  bool        `json:"tokenIsKey,omitempty"`
	Tenant      string      `json:"tenant,omitempty"`
	Environment string      `json:"environment,omitempty"`
	Tenants     []tenantRef `json:"tenants,omitempty"`
	Email       string      `json:"email,omitempty"`
}

func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "licenserail", "config.json")
}

func loadConfig() *config {
	c := &config{APIURL: "https://api.licenserail.com", Environment: "test"}
	if b, err := os.ReadFile(configPath()); err == nil {
		_ = json.Unmarshal(b, c)
	}
	if v := os.Getenv("LICENSERAIL_API_URL"); v != "" {
		c.APIURL = v
	}
	if v := os.Getenv("LICENSERAIL_API_KEY"); v != "" {
		c.Token, c.TokenIsKey = v, true
	}
	if v := os.Getenv("LICENSERAIL_ENV"); v != "" {
		c.Environment = v
	}
	return c
}

func (c *config) save() error {
	if err := os.MkdirAll(filepath.Dir(configPath()), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(configPath(), b, 0o600)
}

// ---------------------------------------------------------------- arguments

type args struct {
	pos    []string
	flags  map[string][]string
	bools  map[string]bool
}

var boolFlags = map[string]bool{"json": true, "yes": true, "live": true, "restricted": true, "floating": true, "pem": true, "agent": true, "clear-expiry": true}

func parse(raw []string) args {
	a := args{flags: map[string][]string{}, bools: map[string]bool{}}
	for i := 0; i < len(raw); i++ {
		s := raw[i]
		if !strings.HasPrefix(s, "--") {
			a.pos = append(a.pos, s)
			continue
		}
		name := strings.TrimPrefix(s, "--")
		if k, v, ok := strings.Cut(name, "="); ok {
			a.flags[k] = append(a.flags[k], v)
		} else if boolFlags[name] || i+1 >= len(raw) || strings.HasPrefix(raw[i+1], "--") {
			a.bools[name] = true
		} else {
			a.flags[name] = append(a.flags[name], raw[i+1])
			i++
		}
	}
	return a
}

func (a args) get(name string) string {
	if v := a.flags[name]; len(v) > 0 {
		return v[len(v)-1]
	}
	return ""
}

func (a args) arg(i int) string {
	if i < len(a.pos) {
		return a.pos[i]
	}
	return ""
}

// ---------------------------------------------------------------- HTTP

type apiError struct {
	Status int
	Body   map[string]interface{}
}

func (e *apiError) Error() string {
	if er, ok := e.Body["error"].(map[string]interface{}); ok {
		return fmt.Sprintf("%v (%v)", er["message"], er["code"])
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

type client struct {
	cfg      *config
	json     bool
	approval string
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *client) do(method, path string, body interface{}) (map[string]interface{}, error) {
	if c.cfg.Token == "" && !strings.HasPrefix(path, "/api/auth/") {
		return nil, errors.New("not signed in: run `licenserail login`")
	}
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	if !strings.HasPrefix(path, "/api/") {
		path = "/api/v2" + path
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.APIURL, "/")+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "licenserail-cli/"+version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if !c.cfg.TokenIsKey {
		req.Header.Set("X-Environment", c.cfg.Environment)
		if c.cfg.Tenant != "" {
			req.Header.Set("X-Tenant", c.cfg.Tenant)
		}
	}
	if method != http.MethodGet {
		req.Header.Set("Idempotency-Key", "cli-"+newID())
	}
	if c.approval != "" {
		req.Header.Set("Approval-Id", c.approval)
	}
	res, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := map[string]interface{}{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("unexpected response (%d): %s", res.StatusCode, string(raw))
		}
	}
	if res.StatusCode >= 400 {
		return out, &apiError{res.StatusCode, out}
	}
	return out, nil
}

// ---------------------------------------------------------------- output

func (c *client) print(v map[string]interface{}, columns ...string) {
	if c.json {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
		return
	}
	if data, ok := v["data"].([]interface{}); ok {
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, strings.ToUpper(strings.Join(columns, "\t")))
		for _, item := range data {
			m, _ := item.(map[string]interface{})
			cells := make([]string, len(columns))
			for i, col := range columns {
				cells[i] = cell(m[col])
			}
			fmt.Fprintln(w, strings.Join(cells, "\t"))
		}
		w.Flush()
		if more, _ := v["hasMore"].(bool); more {
			fmt.Printf("More: --starting-after %v\n", v["nextCursor"])
		}
		return
	}
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\n", k, cell(v[k]))
	}
	w.Flush()
}

func cell(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "-"
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func fail(err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		if er, ok := ae.Body["error"].(map[string]interface{}); ok && (er["code"] == "approval_required" || er["code"] == "approval_pending") {
			fmt.Fprintf(os.Stderr, "This Live action needs a person's approval.\nApprove it here: %v\nThen run the same command again with --approval %v\n", er["approvalUrl"], er["approvalId"])
			os.Exit(3)
		}
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func confirm(a args, cfg *config, what string) {
	if a.bools["yes"] || cfg.Environment != "live" && !strings.Contains(cfg.Token, "_live_") {
		return
	}
	fmt.Fprintf(os.Stderr, "%s in LIVE. Continue? [y/N] ", what)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.ToLower(strings.TrimSpace(line)) != "y" {
		fmt.Fprintln(os.Stderr, "Cancelled.")
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`licenserail ` + version + ` — LicenseRail from the command line (alias: lr)

  login [--email you@company.com] [--token <api-key>]   sign in with an emailed code (first sign-in creates your organization)
  logout | whoami
  tenants list | use <slug>          env use live|test | show
  products list|get <id>|create --code --name [--offline-grace-days N]|update <id> [--name]|delete <id>
  features list --product <id>|create --product <id> --code --name|delete --product <id> <featureId>
  customers list|get <id>|create --name [--email --contact]|update <id> [--name --email]|delete <id>
  licenses list [--product --customer --status --q]|get <id>
           create --product <id> --customer <id> [--kind trial] [--expires 2027-01-01] [--seats N] [--floating --lease-minutes N]
                  [--feature code ...] [--meta k=v ...] [--count N]
           update <id> [--expires date|none] [--seats N] [--feature code ...] [--meta k=v ...]
           suspend|resume|revoke|delete <id>    transfer <id> --customer <id>
  activations list --license <id> | deactivate <id>
  events list [--type license.*] | tail
  keys list | create --name [--restricted --scope licenses:read ...] [--agent] | revoke <id>
  webhooks list | create --url <https://...> [--event license.* ...] | test <id> | deliveries <id> | delete <id>
  public-key [--pem]
  test activate [--product <code>] [--key <license-key>]
  init <dotnet|typescript|python|go|rust|java|swift|cpp|php> [--product <code>]
  mcp config [--client claude|cursor|vscode]
  billing balance | usage | top-up <dollars>
  docs search <query>

Global: --json (machine output), --yes (skip Live confirmation), --approval <apr_...> (repeat an approved action).
Env: LICENSERAIL_API_KEY, LICENSERAIL_ENV, LICENSERAIL_API_URL.
`)
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		usage()
		return
	}
	if os.Args[1] == "version" || os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	cfg := loadConfig()
	a := parse(os.Args[2:])
	c := &client{cfg: cfg, json: a.bools["json"], approval: a.get("approval")}
	if err := run(c, os.Args[1], a); err != nil {
		fail(err)
	}
}

// meta turns --meta k=v pairs into an object (numbers and booleans are kept as such).
func meta(a args) map[string]interface{} {
	m := map[string]interface{}{}
	for _, kv := range a.flags["meta"] {
		k, v, _ := strings.Cut(kv, "=")
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			m[k] = n
		} else if b, err := strconv.ParseBool(v); err == nil {
			m[k] = b
		} else if v == "null" {
			m[k] = nil
		} else {
			m[k] = v
		}
	}
	return m
}

func expires(v string) interface{} {
	if v == "" {
		return nil
	}
	if v == "none" || v == "never" {
		return nil
	}
	if len(v) == 10 {
		return v + "T23:59:59Z"
	}
	return v
}

func q(params map[string]string) string {
	vals := url.Values{}
	for k, v := range params {
		if v != "" {
			vals.Set(k, v)
		}
	}
	if len(vals) == 0 {
		return ""
	}
	return "?" + vals.Encode()
}
