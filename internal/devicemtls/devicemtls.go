// SPDX-License-Identifier: AGPL-3.0-or-later

// Package devicemtls derives a device identity from the Envoy
// X-Forwarded-Client-Cert header for the public admin edge ("admin access
// without WireGuard"): Envoy terminates device-bound client-cert mTLS for
// *.ops hosts and forwards the verified leaf via XFCC; Talon trusts that
// header ONLY when the Linkerd caller identity (l5d-client-id) is the
// configured Envoy service account, and otherwise strips it.
package devicemtls

import (
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/dogukanturhal/talon/internal/xfcc"
)

// Header names.
const (
	XFCCHeader     = "X-Forwarded-Client-Cert"
	CallerIDHeader = "L5d-Client-Id"
)

// Certificate identity conventions (jess browser-cert contract C1).
const (
	deviceSPIFFEPrefix = "spiffe://example.com/device/"
	browserKindURI     = "urn:hexxlock:cert-kind:browser"

	KindBrowser = "browser"
	KindDevice  = "device"
	// ChannelDeviceMTLS is the Rego input channel value for this path.
	ChannelDeviceMTLS = "device-mtls"
)

// Mode selects how a failed device check is handled.
type Mode string

const (
	ModeAudit   Mode = "audit"
	ModeEnforce Mode = "enforce"
)

// ParseMode maps TALON_DEVICE_MTLS_MODE to a Mode; anything but "enforce"
// is audit (fail-open on typos is deliberate: audit never changes responses).
func ParseMode(s string) Mode {
	if strings.EqualFold(strings.TrimSpace(s), string(ModeEnforce)) {
		return ModeEnforce
	}
	return ModeAudit
}

// Config is the runtime configuration.
type Config struct {
	// TrustedClientID is the Linkerd identity of the Envoy gateway whose XFCC
	// is believed. Empty disables the feature (XFCC is always stripped).
	TrustedClientID string
	Mode            Mode
	// Hosts limits the check to these request hosts (lower-case). Empty = all.
	Hosts []string
}

// Enabled reports whether device-mTLS evaluation is configured.
func (c *Config) Enabled() bool { return c != nil && c.TrustedClientID != "" }

// AppliesTo reports whether the check covers host.
func (c *Config) AppliesTo(host string) bool {
	if !c.Enabled() {
		return false
	}
	if len(c.Hosts) == 0 {
		return true
	}
	h := strings.ToLower(host)
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	for _, x := range c.Hosts {
		if strings.EqualFold(x, h) {
			return true
		}
	}
	return false
}

// Identity is the Rego-facing projection (input.device_mtls).
type Identity struct {
	Present  bool   `json:"present"`
	Valid    bool   `json:"valid"`
	DeviceID string `json:"device_id"`
	Kind     string `json:"kind"`
	Channel  string `json:"channel"`
}

// Resolve enforces the trust rule and returns the identity. The XFCC header
// is ALWAYS removed from h so nothing downstream (upstream apps, other
// readers) can see or be fooled by it. It is parsed only when cfg is enabled
// and the caller's l5d-client-id equals cfg.TrustedClientID. Time is injected
// for tests.
func Resolve(cfg *Config, h http.Header, now time.Time) Identity {
	raw := h.Get(XFCCHeader)
	caller := h.Get(CallerIDHeader)
	h.Del(XFCCHeader)
	id := Identity{Channel: ChannelDeviceMTLS}
	if raw == "" || !cfg.Enabled() || caller != cfg.TrustedClientID {
		return id
	}
	leaf, err := xfcc.Parse(raw)
	if err != nil {
		// Present but unusable: report present, not valid.
		id.Present = true
		return id
	}
	id.Present = true
	id.DeviceID, id.Kind = fromCert(leaf)
	id.Valid = id.DeviceID != "" && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
	return id
}

func fromCert(c *x509.Certificate) (deviceID, kind string) {
	kind = KindDevice
	for _, u := range c.URIs {
		s := u.String()
		switch {
		case s == browserKindURI:
			kind = KindBrowser
		case strings.HasPrefix(s, deviceSPIFFEPrefix) && deviceID == "":
			deviceID = strings.TrimPrefix(s, deviceSPIFFEPrefix)
		}
	}
	return deviceID, kind
}

// PostureDeviceID extracts the device UUID from a posture JWS `sub`:
// "spiffe://example.com/device/<uuid>", "device:<uuid>" or a bare uuid.
func PostureDeviceID(sub string) string {
	sub = strings.TrimSpace(sub)
	sub = strings.TrimPrefix(sub, deviceSPIFFEPrefix)
	sub = strings.TrimPrefix(sub, "device:")
	return sub
}

// Deny reasons (stable audit/metric labels).
const (
	ReasonAbsent          = "device_mtls_absent"
	ReasonInvalid         = "device_mtls_invalid"
	ReasonPostureMismatch = "device_mtls_posture_mismatch"
)

// Check returns "" when the request satisfies the device-mTLS policy, else
// the deny reason. postureSub is the verified posture JWS subject ("" when
// no posture was verified, in which case no binding is checked).
func Check(id Identity, postureSub string) string {
	if !id.Present {
		return ReasonAbsent
	}
	if !id.Valid {
		return ReasonInvalid
	}
	if postureSub != "" && !strings.EqualFold(PostureDeviceID(postureSub), id.DeviceID) {
		return ReasonPostureMismatch
	}
	return ""
}

// Decision is the outcome of Decide.
type Decision struct {
	// Reason is "" when the request passes (or the check does not apply).
	Reason string
	// Deny is true only in enforce mode with a non-empty Reason. In audit
	// mode callers log would_deny and let the request through.
	Deny bool
}

// Decide applies the policy for one request. Hosts outside cfg.Hosts are
// only checked when a device identity is actually present (binding only);
// their absence is never a failure.
func Decide(cfg *Config, id Identity, postureSub, host string) Decision {
	if !cfg.Enabled() {
		return Decision{}
	}
	if !cfg.AppliesTo(host) && !id.Present {
		return Decision{}
	}
	reason := Check(id, postureSub)
	return Decision{Reason: reason, Deny: reason != "" && cfg.Mode == ModeEnforce}
}
