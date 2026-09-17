// SPDX-License-Identifier: AGPL-3.0-or-later

// Package posturesigner is the JWS issuer for the ZTNA Phase 4 posture
// heartbeat protocol (ADR 0040 D-003).
//
// Wire contract (locked):
//
//   - Transport: HTTP/JSON over Linkerd mTLS (NOT gRPC — mirrors
//     Cloudflare WARP / Tailscale precedent of HTTP-over-mTLS for agent
//     heartbeats; gRPC dependency-weight not justified for one endpoint).
//   - Signer key: Vault Transit `posture-signer` rsa-2048 RS256 — the
//     private key NEVER leaves Vault (NIST SP 800-57 §5.6.4 key
//     containment).
//   - Cadence: TIER_CORP every 5min ±30s jitter; TIER_BYOD every 15min
//     ±90s. Server accept window = cadence + 60s (D-003).
//   - Replay defence: BOTH timestamp window (5min) AND nonce single-use
//     in-memory cache (10min TTL dedup window covers 2× the TIER_CORP
//     cadence).
package posturesigner

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Tier enumerates trust levels for incoming heartbeats (ADR 0040 D-006).
type Tier string

const (
	TierCorp Tier = "TIER_CORP"
	TierBYOD Tier = "TIER_BYOD"
)

// nonceBytesRequired is the exact number of raw bytes a valid nonce
// must represent when base64url-decoded. 32 raw bytes = 256 bits, which
// is sufficient entropy to make birthday collision probability negligible
// even across the 10-minute dedup window at 5-minute heartbeat cadence.
const nonceBytesRequired = 32

// iatToleranceWindow is the maximum absolute drift between agent-claimed
// iat and server clock. ±30s matches the HexxLock Access agent's
// clock-sync contract (NTP ±500ms practical; 30s is generous but still
// rejects anything that slipped through an NTP-divorced device).
const iatToleranceWindow = 30 * time.Second

// Validation sentinel errors. Use errors.Is to dispatch on these —
// the string-matching helpers isClockSkewError / isTierError in
// server.go previously grepped error messages, which broke the
// moment a message was reformatted. Sentinel-based dispatch is
// stable across rewording.
var (
	// ErrClockSkew is returned (wrapped in a descriptive error) when
	// the heartbeat's iat field falls outside the asymmetric clock
	// window (±30s past, ±2s future).
	ErrClockSkew = errors.New("posturesigner: heartbeat iat clock skew")

	// ErrTierInvalid is returned when the heartbeat's tier is neither
	// TIER_CORP nor TIER_BYOD.
	ErrTierInvalid = errors.New("posturesigner: heartbeat tier invalid")
)

// HeartbeatRequest is the JSON body sent by the HexxLock Access agent.
// The agent calls POST /v1/sign-posture with Content-Type: application/json.
//
// Wire notes:
//   - device_uuid: UUIDv4 matching the SPIFFE SAN on the client TLS cert
//     (`spiffe://hexxlock.com/device/<uuid>`). Server cross-checks these
//     to prevent a stolen heartbeat from a different device.
//   - nonce: 32-byte random value from the agent, base64url-encoded
//     (RFC 4648 §5, no padding). Single-use; server rejects a re-used
//     nonce within the 10-minute dedup window.
//   - iat: Unix epoch seconds (int64). Server validates: |now - iat| ≤ 30s.
//   - compliance: key/value map matching the shape expected by
//     internal/posture.Evaluate — callers must match the posture.rawClaims
//     compliance field exactly.
type HeartbeatRequest struct {
	DeviceUUID string         `json:"device_uuid"`
	UserSub    string         `json:"user_sub,omitempty"`
	Tier       Tier           `json:"tier"`
	Nonce      string         `json:"nonce"`
	IAT        int64          `json:"iat"`
	Compliance map[string]any `json:"compliance"`

	// deviceCertThumbprint is the SHA-256 of the verified device leaf
	// cert in base64url-no-pad form (RFC 8705 cnf.x5t#S256 value). The
	// server populates this AFTER VerifyRequest returns the verified
	// leaf and BEFORE IssueJWS; it is then embedded as the cnf claim
	// in the signed JWS so downstream verifiers (Talon edge) can
	// reject any JWS presented over an mTLS connection whose cert
	// thumbprint doesn't match. Closes the cross-connection-replay
	// attack class.
	//
	// Unexported on purpose: agents do not set this. The struct tag
	// is intentionally absent so json.Unmarshal cannot populate it
	// from the request body — but it WILL be visible to the issuer
	// via the struct pointer.
	deviceCertThumbprint string `json:"-"`
}

// DeviceCertThumbprint returns the RFC 8705 cnf.x5t#S256 value the
// server attached for this heartbeat. Empty before VerifyRequest has
// returned; populated by the handler immediately after.
func (r *HeartbeatRequest) DeviceCertThumbprint() string {
	return r.deviceCertThumbprint
}

// HeartbeatResponse is the JSON body returned on success.
// The JWS is compact-serialized RS256 and can be placed directly into
// the X-Talon-Posture header on subsequent requests.
type HeartbeatResponse struct {
	JWS       string `json:"jws"`
	ExpiresAt string `json:"expires_at"` // RFC3339
}

// Validate performs field-level validation of a LIVE heartbeat, including
// the iat clock-skew window. It does NOT perform replay detection (that
// requires the Nonce cache) or device-cert chain validation (that requires
// the x509 CertPool). The caller is responsible for sequencing these checks.
func (r *HeartbeatRequest) Validate(now time.Time) error {
	errs := r.validateStatic()

	// IAT clock-skew check — ASYMMETRIC. Past skew up to the tolerance
	// window is admitted (real-world clocks drift; NTP sync is not
	// instantaneous). Future timestamps are admitted only to a tight
	// ±2s ceiling: a future iat is far less plausible from honest
	// drift (devices' monotonic clocks don't run fast), and a
	// permissive future window is a replay vector — an attacker
	// harvesting a nonce can forward-stamp it to keep their own
	// heartbeat "fresh" past the nonce dedup TTL.
	//
	// This gate is LIVE-PATH ONLY. A report replayed through the offline
	// reconcile path (ValidateHistorical) is, by construction, minutes-to-
	// hours old — that is the entire reason /v1/reconcile-posture exists —
	// so freshness cannot and must not apply there.
	if r.IAT != 0 {
		iat := time.Unix(r.IAT, 0)
		skew := now.Sub(iat) // positive = iat is in the past
		// Add 1s grace for Unix-second truncation: time.Unix(t.Unix(), 0)
		// can be up to 999ms earlier than the original time.Time; without
		// the grace, exact-edge tests flake. Tight enough that the
		// security property (5-min cadence) is unaffected.
		const truncationGrace = time.Second
		const futureSkewCeiling = 2 * time.Second
		switch {
		case skew > iatToleranceWindow+truncationGrace:
			errs = append(errs, fmt.Errorf("%w: %s exceeds past tolerance ±%s", ErrClockSkew, skew.Round(time.Millisecond), iatToleranceWindow))
		case -skew > futureSkewCeiling+truncationGrace:
			errs = append(errs, fmt.Errorf("%w: timestamp is %s in the future (ceiling ±%s) — clock attack or device clock-divorced", ErrClockSkew, (-skew).Round(time.Millisecond), futureSkewCeiling))
		}
	}

	return errors.Join(errs...)
}

// ValidateHistorical validates a reconciled (offline-spooled) heartbeat that
// arrives via POST /v1/reconcile-posture. It runs every field-level check
// Validate does EXCEPT the iat clock-skew window: a report captured while the
// signer was unreachable is by definition stale, so the liveness freshness
// gate cannot (and must not) apply. The record's real observation time is
// carried out-of-band in ReconcileRecord.CapturedAt. device_uuid / tier /
// nonce / compliance are still fully validated so a corrupt spool record is
// rejected with 400.
func (r *HeartbeatRequest) ValidateHistorical() error {
	return errors.Join(r.validateStatic()...)
}

// validateStatic runs the clock-INDEPENDENT field checks shared by the live
// (Validate) and reconcile (ValidateHistorical) paths: device_uuid UUIDv4,
// tier enum, nonce shape, iat presence, and the compliance-map shape/size.
// The live path layers the iat clock-skew window on top of this set.
func (r *HeartbeatRequest) validateStatic() []error {
	var errs []error

	// UUIDv4 validation.
	if _, err := uuid.Parse(r.DeviceUUID); err != nil {
		errs = append(errs, fmt.Errorf("device_uuid: invalid UUIDv4: %w", err))
	} else {
		parsed, _ := uuid.Parse(r.DeviceUUID)
		if parsed.Version() != 4 {
			errs = append(errs, fmt.Errorf("device_uuid: must be UUIDv4, got v%d", parsed.Version()))
		}
	}

	// Tier enum validation.
	switch r.Tier {
	case TierCorp, TierBYOD:
		// valid
	default:
		errs = append(errs, fmt.Errorf("%w: %q; must be TIER_CORP or TIER_BYOD", ErrTierInvalid, r.Tier))
	}

	// Nonce: must be non-empty base64url-decodable and exactly 32 raw bytes.
	if r.Nonce == "" {
		errs = append(errs, errors.New("nonce: required"))
	} else {
		raw, err := base64.RawURLEncoding.DecodeString(r.Nonce)
		if err != nil {
			errs = append(errs, fmt.Errorf("nonce: base64url decode failed: %w", err))
		} else if len(raw) != nonceBytesRequired {
			errs = append(errs, fmt.Errorf("nonce: must be exactly %d bytes, got %d", nonceBytesRequired, len(raw)))
		}
	}

	// IAT presence. The clock-skew window is applied by Validate only.
	if r.IAT == 0 {
		errs = append(errs, errors.New("iat: required"))
	}

	// Compliance map must be present (may be empty but not nil, for
	// explicitly device-posture-only assertions from BYOD devices that
	// have no EDR). A nil map indicates the agent forgot to send the
	// field; an empty map is a valid assertion of "no compliance facts".
	if r.Compliance == nil {
		errs = append(errs, errors.New("compliance: required (use {} for no facts)"))
	}

	// Compliance map size + depth cap — DoS guard. Without this, a
	// 32-KB body of nested objects burns CPU on JSON allocation +
	// per-key tier checks. 64 top-level keys is generous (typical
	// posture has ~12: disk_encrypted, edr_running, edr_signature_age,
	// screen_lock_min, fde_aes, fde_xts, os_version, os_patch_age,
	// av_running, av_signature_age, firewall_enabled, secure_boot —
	// plus any vendor-specific extensions). Depth-2 caps nesting; the
	// posture shape is documented as a flat map per ADR 0040 D-002.
	const maxComplianceKeys = 64
	const maxComplianceDepth = 2
	if len(r.Compliance) > maxComplianceKeys {
		errs = append(errs, fmt.Errorf("compliance: too many keys (%d > %d) — flat posture map only", len(r.Compliance), maxComplianceKeys))
	}
	if d := complianceDepth(r.Compliance, 0); d > maxComplianceDepth {
		errs = append(errs, fmt.Errorf("compliance: nested too deep (depth=%d > %d) — flat posture map only", d, maxComplianceDepth))
	}

	return errs
}

// complianceDepth measures the deepest nested-map level in the
// compliance payload. Top-level map = depth 1; a map containing a
// map = depth 2; etc. Used to reject attacker-crafted deeply-nested
// payloads that would burn CPU on traversal.
func complianceDepth(v any, current int) int {
	current++
	max := current
	switch x := v.(type) {
	case map[string]any:
		for _, val := range x {
			if d := complianceDepth(val, current); d > max {
				max = d
			}
		}
	case []any:
		for _, val := range x {
			if d := complianceDepth(val, current); d > max {
				max = d
			}
		}
	}
	return max
}
