// Package licenserail is the LicenseRail client SDK: offline license verification, activation, refresh and floating leases.
package licenserail

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Unavailable is sent for a fingerprint component that couldn't be read; it never matches.
const Unavailable = "none"

const (
	clockTolerance    = 10 * time.Minute
	issuedAtTolerance = 24 * time.Hour
)

// RevokingCodes are server error codes on which the local license is deleted; any other error keeps it.
var RevokingCodes = map[string]bool{
	"license_not_found": true, "license_suspended": true, "license_expired": true, "activation_revoked": true,
	"wrong_machine": true, "invalid_token": true, "license_revoked": true,
}

// Status is the result of an offline evaluation.
type Status string

const (
	Valid            Status = "Valid"
	Missing          Status = "Missing"
	InvalidSignature Status = "InvalidSignature"
	WrongProduct     Status = "WrongProduct"
	WrongMachine     Status = "WrongMachine"
	Expired          Status = "Expired"
	OfflineTooLong   Status = "OfflineTooLong"
	ClockTampered    Status = "ClockTampered"
	Unverified       Status = "Unverified"
	Suspended        Status = "Suspended"
)

// Fingerprint holds the hashed device components.
type Fingerprint struct {
	MachineID string `json:"machineId"`
	DiskID    string `json:"diskId"`
	HostName  string `json:"hostName"`
	BoardID   string `json:"boardId"`
	OS        string `json:"os,omitempty"`
}

// Payload is the signed license content.
type Payload struct {
	LicenseID      string                 `json:"licenseId"`
	ActivationID   string                 `json:"activationId"`
	LicenseKey     string                 `json:"licenseKey"`
	Product        string                 `json:"product"`
	Customer       string                 `json:"customer"`
	Kind           string                 `json:"kind"`
	ExpiresAt      *time.Time             `json:"expiresAt"`
	IssuedAt       time.Time              `json:"issuedAt"`
	RefreshAfter   time.Time              `json:"refreshAfter"`
	OfflineUntil   time.Time              `json:"offlineUntil"`
	Fingerprint    Fingerprint            `json:"fingerprint"`
	Suspended      bool                   `json:"suspended"`
	EnvironmentID  string                 `json:"environmentId,omitempty"`
	Test           bool                   `json:"test,omitempty"`
	Entitlements   []string               `json:"entitlements,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	Floating       bool                   `json:"floating,omitempty"`
	LeaseExpiresAt *time.Time             `json:"leaseExpiresAt,omitempty"`
}

// HasFeature reports whether the license enables the feature code.
func (p *Payload) HasFeature(code string) bool {
	for _, e := range p.Entitlements {
		if e == code {
			return true
		}
	}
	return false
}

// ParsePublicKey reads a SubjectPublicKeyInfo PEM (P-256).
func ParsePublicKey(pemText string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("licenserail: invalid PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("licenserail: not an EC public key")
	}
	return ec, nil
}

var b64urlChars = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// VerifyToken checks the ECDSA P-256/SHA-256 signature (IEEE P1363 r||s) over the ASCII encoded body and returns the
// payload, or nil when the token is invalid.
func VerifyToken(token string, key *ecdsa.PublicKey) *Payload {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 || !b64urlChars.MatchString(parts[0]) || !b64urlChars.MatchString(parts[1]) {
		return nil
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(sig) != 64 {
		return nil
	}
	digest := sha256.Sum256([]byte(parts[0]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil
	}
	return &p
}

// HashComponent is hex(SHA256(vendor + ":" + product + ":" + part + ":" + upper(trim(raw)))); blank raw gives "none".
// vendor is the organization ID (ten_..., never changes).
func HashComponent(vendor, product, part, raw string) string {
	t := strings.TrimSpace(raw)
	if t == "" {
		return Unavailable
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%s", vendor, product, part, strings.ToUpper(t))))
	return hex.EncodeToString(sum[:])
}

func available(v string) bool { return v != "" && v != Unavailable }
func same(a, b string) bool    { return available(a) && a == b }

// Matches reports whether presented is the device registered was issued for (call on the registered fingerprint).
func (registered Fingerprint) Matches(presented Fingerprint) bool {
	if registered.OS != "" && presented.OS != "" && !strings.EqualFold(registered.OS, presented.OS) {
		return false
	}
	n := 0
	if same(registered.MachineID, presented.MachineID) {
		n++
	}
	if same(registered.DiskID, presented.DiskID) {
		n++
	}
	if same(registered.HostName, presented.HostName) {
		n++
	}
	if available(registered.BoardID) {
		return same(registered.BoardID, presented.BoardID) && n >= 1
	}
	return n >= 2
}

// Evaluate is the offline check (identical in every SDK). lastSeen nil means the run history is missing.
func Evaluate(p *Payload, product string, machine Fingerprint, now time.Time, lastSeen *time.Time) Status {
	switch {
	case p == nil:
		return InvalidSignature
	case !strings.EqualFold(p.Product, product):
		return WrongProduct
	case !p.Fingerprint.Matches(machine):
		return WrongMachine
	case p.Suspended:
		return Suspended
	case lastSeen == nil:
		return Unverified
	case now.Add(issuedAtTolerance).Before(p.IssuedAt) || now.Add(clockTolerance).Before(*lastSeen):
		return ClockTampered
	case p.ExpiresAt != nil && !now.Before(*p.ExpiresAt):
		return Expired
	case !now.Before(p.OfflineUntil):
		return OfflineTooLong
	}
	return Valid
}

func historyMac(ms, vendor, product string, m Fingerprint) string {
	key := sha256.Sum256([]byte(fmt.Sprintf("%s:run-history:%s:%s:%s", vendor, product, m.MachineID, m.BoardID)))
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte(ms))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))[:32]
}

func encodeHistory(at time.Time, vendor, product string, m Fingerprint) string {
	ms := strconv.FormatInt(at.UnixMilli(), 10)
	return ms + "." + historyMac(ms, vendor, product, m)
}

func decodeHistory(v, vendor, product string, m Fingerprint) *time.Time {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) != 2 {
		return nil
	}
	ms, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || ms <= 0 || !hmac.Equal([]byte(parts[1]), []byte(historyMac(parts[0], vendor, product, m))) {
		return nil
	}
	t := time.UnixMilli(ms).UTC()
	return &t
}
