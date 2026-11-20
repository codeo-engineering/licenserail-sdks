package licenserail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func load(t *testing.T, name string, v interface{}) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "test-vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestTokens(t *testing.T) {
	var v struct {
		PublicKeyPem string `json:"publicKeyPem"`
		Cases        []struct {
			Name   string `json:"name"`
			Token  string `json:"token"`
			Expect struct {
				SignatureValid bool                   `json:"signatureValid"`
				Payload        map[string]interface{} `json:"payload"`
			} `json:"expect"`
		} `json:"cases"`
	}
	load(t, "tokens.json", &v)
	key, err := ParsePublicKey(v.PublicKeyPem)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		p := VerifyToken(c.Token, key)
		if (p != nil) != c.Expect.SignatureValid {
			t.Errorf("%s: signature valid = %v", c.Name, p != nil)
			continue
		}
		if p == nil || c.Expect.Payload == nil {
			continue
		}
		var actual map[string]interface{}
		raw, _ := json.Marshal(p)
		_ = json.Unmarshal(raw, &actual)
		for _, k := range []string{"licenseKey", "product", "customer", "kind", "suspended", "entitlements", "metadata", "floating", "test"} {
			if exp, ok := c.Expect.Payload[k]; ok && !reflect.DeepEqual(exp, actual[k]) {
				t.Errorf("%s: %s = %v, want %v", c.Name, k, actual[k], exp)
			}
		}
		if exp, ok := c.Expect.Payload["offlineUntil"].(string); ok {
			want, _ := time.Parse(time.RFC3339, exp)
			if !want.Equal(p.OfflineUntil) {
				t.Errorf("%s: offlineUntil", c.Name)
			}
		}
	}
}

func TestFingerprint(t *testing.T) {
	var v struct {
		Cases []struct {
			Vendor  string  `json:"vendor"`
			Product string  `json:"product"`
			Part    string  `json:"part"`
			Raw     *string `json:"raw"`
			Hash    string  `json:"hash"`
		} `json:"cases"`
	}
	load(t, "fingerprint.json", &v)
	for _, c := range v.Cases {
		raw := ""
		if c.Raw != nil {
			raw = *c.Raw
		}
		if got := HashComponent(c.Vendor, c.Product, c.Part, raw); got != c.Hash {
			t.Errorf("%s %q: %s, want %s", c.Part, raw, got, c.Hash)
		}
	}
}

func TestMatch(t *testing.T) {
	var v struct {
		Cases []struct {
			Name       string      `json:"name"`
			Registered Fingerprint `json:"registered"`
			Presented  Fingerprint `json:"presented"`
			Matches    bool        `json:"matches"`
		} `json:"cases"`
	}
	load(t, "match.json", &v)
	for _, c := range v.Cases {
		if c.Registered.Matches(c.Presented) != c.Matches {
			t.Errorf("%s: want %v", c.Name, c.Matches)
		}
	}
}

func TestEvaluate(t *testing.T) {
	var v struct {
		PublicKeyPem string `json:"publicKeyPem"`
		Cases        []struct {
			Name     string      `json:"name"`
			Token    string      `json:"token"`
			Product  string      `json:"product"`
			Machine  Fingerprint `json:"machine"`
			Now      time.Time   `json:"now"`
			LastSeen *time.Time  `json:"lastSeen"`
			Status   string      `json:"status"`
		} `json:"cases"`
	}
	load(t, "evaluate.json", &v)
	key, _ := ParsePublicKey(v.PublicKeyPem)
	for _, c := range v.Cases {
		if got := Evaluate(VerifyToken(c.Token, key), c.Product, c.Machine, c.Now, c.LastSeen); string(got) != c.Status {
			t.Errorf("%s: %s, want %s", c.Name, got, c.Status)
		}
	}
}
