// SPDX-License-Identifier: AGPL-3.0-or-later

package caep

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Errors that callers may want to discriminate.
var (
	ErrParse              = errors.New("caep: SET parse failed")
	ErrSignature          = errors.New("caep: SET signature verification failed")
	ErrIssuerMismatch     = errors.New("caep: SET iss does not match expected")
	ErrAudienceMismatch   = errors.New("caep: SET aud does not include receiver")
	ErrReplay             = errors.New("caep: SET jti replay")
	ErrTooOld             = errors.New("caep: SET iat outside acceptance window")
	ErrEmptyEvents        = errors.New("caep: SET has no events claim")
	ErrUnknownSubjectFmt  = errors.New("caep: subject format not supported")
)

// SubjectRevoker is the surface the receiver invokes to act on a
// session-revoked / credential-change / account-disabled event. The
// session store implements this directly via RevokeBySubject; tests
// pass a recording stub.
//
// Returning the count of revoked sessions is used to emit accurate
// audit + metrics — zero is not an error (session may have expired
// naturally between transmitter dispatch and receiver processing).
type SubjectRevoker interface {
	RevokeBySubject(ctx context.Context, iss, sub, reason string) (revoked int, err error)
}

// ReplayCache mirrors the interface in package dpop. The receiver
// records the SET jti to defend against duplicate delivery from
// transmitter retries.
type ReplayCache interface {
	SeenOrAdd(jti string, ttl time.Duration) bool
}

// AuditEmitter is the slog/audit hook. The receiver emits
// `caep.received`, `caep.revoke`, `caep.risk_change` events. nil
// disables — callers should wire the audit package's emitter.
type AuditEmitter interface {
	Emit(eventType string, fields map[string]any)
}

// JWKSResolver returns the public key(s) the SET signature is
// verified against. The receiver invokes this per call so a JWKS
// rotation propagates without restarting Talon. For Falcon-ID the
// caller wires the same JWKSManager used by svctoken; tests pass a
// static-key resolver.
type JWKSResolver interface {
	Keys(ctx context.Context, kid string) ([]any, error)
}

// ReceiverConfig is the wiring + tunables.
type ReceiverConfig struct {
	// ExpectedIssuer is the iss the SET must carry. For HexxLock this
	// is "https://id.example.com" (Falcon-ID).
	ExpectedIssuer string

	// ExpectedAudience is the receiver's URL. CAEP §4.2 requires the
	// aud claim to include the receiver; typically
	// "https://auth.internal.example.com/caep/events".
	ExpectedAudience string

	// AllowedAlgs constrains the SET signing algorithm. Defaults to
	// {RS256, ES256, EdDSA} — the same posture as the OIDC RP.
	AllowedAlgs []jose.SignatureAlgorithm

	// IATTolerance is the max age of an accepted SET. Default 5min.
	// SETs older than this are rejected to bound replay-window risk
	// even if the jti cache is partitioned.
	IATTolerance time.Duration

	// JTITTL is the replay-cache TTL for the SET jti. Default 24h —
	// generous because SETs are idempotent (re-applying a session-
	// revoke is harmless) but transmitter retries can extend hours.
	JTITTL time.Duration

	// Resolver returns signing keys per kid.
	Resolver JWKSResolver

	// Revoker acts on subject-level events.
	Revoker SubjectRevoker

	// Replay defends against duplicate delivery.
	Replay ReplayCache

	// Audit emits structured events. Optional.
	Audit AuditEmitter

	// Clock is the time source; defaults to time.Now. Tests inject.
	Clock func() time.Time
}

// Receiver verifies + processes CAEP SETs.
type Receiver struct {
	cfg            ReceiverConfig
	allowedAlgsSet map[jose.SignatureAlgorithm]struct{}
}

// NewReceiver returns a configured receiver. Returns an error when
// any required wiring is missing — callers cannot silently disable
// signature verification or replay defense.
func NewReceiver(cfg ReceiverConfig) (*Receiver, error) {
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("caep: ExpectedIssuer is required")
	}
	if cfg.ExpectedAudience == "" {
		return nil, errors.New("caep: ExpectedAudience is required")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("caep: Resolver is required")
	}
	if cfg.Revoker == nil {
		return nil, errors.New("caep: Revoker is required")
	}
	if cfg.Replay == nil {
		return nil, errors.New("caep: Replay is required")
	}
	algs := cfg.AllowedAlgs
	if len(algs) == 0 {
		algs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.EdDSA}
	}
	set := make(map[jose.SignatureAlgorithm]struct{}, len(algs))
	for _, a := range algs {
		set[a] = struct{}{}
	}
	if cfg.IATTolerance == 0 {
		cfg.IATTolerance = 5 * time.Minute
	}
	if cfg.JTITTL == 0 {
		cfg.JTITTL = 24 * time.Hour
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Receiver{cfg: cfg, allowedAlgsSet: set}, nil
}

// Result describes the receiver's per-SET outcome. Returned for
// observability + HTTP-layer logging.
type Result struct {
	JTI            string
	EventTypes     []string
	RevokedSubject string
	RevokedCount   int
	IgnoredEvents  []string // event types received but with no action taken
}

// ProcessSET verifies + dispatches one SET. Returns ErrXxx on
// validation failure; the HTTP handler maps these to 4xx/5xx.
//
// IMPORTANT: ProcessSET is fail-closed. Any unrecoverable error
// short-circuits without firing partial revocations.
func (r *Receiver) ProcessSET(ctx context.Context, setJWT string) (*Result, error) {
	algs := r.permittedAlgs()
	parsed, err := jwt.ParseSigned(setJWT, algs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if len(parsed.Headers) != 1 {
		return nil, fmt.Errorf("%w: expected single header, got %d", ErrParse, len(parsed.Headers))
	}
	hdr := parsed.Headers[0]
	alg := jose.SignatureAlgorithm(hdr.Algorithm)
	if _, ok := r.allowedAlgsSet[alg]; !ok {
		return nil, fmt.Errorf("%w: alg %s not permitted", ErrSignature, alg)
	}

	// Resolve signing key.
	keys, err := r.cfg.Resolver.Keys(ctx, hdr.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve kid %q: %w", ErrSignature, hdr.KeyID, err)
	}
	var claims SETClaims
	var verifyErr error
	for _, k := range keys {
		if err := parsed.Claims(k, &claims); err == nil {
			verifyErr = nil
			break
		} else {
			verifyErr = err
		}
	}
	if verifyErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, verifyErr)
	}

	// Validate envelope.
	if claims.Iss != r.cfg.ExpectedIssuer {
		return nil, fmt.Errorf("%w: got %q want %q", ErrIssuerMismatch, claims.Iss, r.cfg.ExpectedIssuer)
	}
	if !claims.Aud.contains(r.cfg.ExpectedAudience) {
		return nil, fmt.Errorf("%w: receiver %q not in aud %v", ErrAudienceMismatch, r.cfg.ExpectedAudience, []string(claims.Aud))
	}
	now := r.cfg.Clock()
	if claims.IAT > 0 {
		age := now.Sub(time.Unix(claims.IAT, 0))
		if age > r.cfg.IATTolerance || age < -r.cfg.IATTolerance {
			return nil, fmt.Errorf("%w: age %s tolerance ±%s", ErrTooOld, age, r.cfg.IATTolerance)
		}
	}
	if claims.JTI == "" {
		return nil, fmt.Errorf("%w: missing jti", ErrParse)
	}
	if r.cfg.Replay.SeenOrAdd(claims.JTI, r.cfg.JTITTL) {
		return nil, ErrReplay
	}
	if len(claims.Events) == 0 {
		return nil, ErrEmptyEvents
	}

	out := &Result{JTI: claims.JTI}
	for eventType, payload := range claims.Events {
		out.EventTypes = append(out.EventTypes, eventType)
		switch eventType {
		case EventSessionRevoked,
			EventCredentialChange,
			EventAccountDisabled,
			EventAccountPurged,
			EventAccountCredentialChangeRequired:
			iss, sub, ok := r.normalizeSubject(payload)
			if !ok {
				return nil, fmt.Errorf("%w: format %q", ErrUnknownSubjectFmt, payload.Subject.Format)
			}
			reason := r.deriveReason(eventType, payload)
			n, err := r.cfg.Revoker.RevokeBySubject(ctx, iss, sub, reason)
			if err != nil {
				return nil, fmt.Errorf("caep: revoke %s/%s: %w", iss, sub, err)
			}
			out.RevokedSubject = sub
			out.RevokedCount = n
			r.emit("caep.revoke", map[string]any{
				"event":     eventType,
				"iss":       iss,
				"sub":       sub,
				"revoked":   n,
				"reason":    reason,
				"jti":       claims.JTI,
			})
		case EventRiskLevelChange,
			EventDeviceComplianceChange,
			EventAssuranceLevelChange:
			// Audit-only events; operator policy can subscribe via
			// Wazuh rule and trigger further action.
			r.emit("caep.signal", map[string]any{
				"event":          eventType,
				"subject_iss":    payload.Subject.Iss,
				"subject_sub":    payload.Subject.Sub,
				"current_level":  payload.CurrentLevel,
				"previous_level": payload.PreviousLevel,
				"jti":            claims.JTI,
			})
			out.IgnoredEvents = append(out.IgnoredEvents, eventType)
		default:
			// Unknown event type — emit `caep.unknown_event` audit but
			// do NOT fail the SET. CAEP transmitters may add event
			// types over time; receivers must tolerate without
			// breaking the wire.
			r.emit("caep.unknown_event", map[string]any{
				"event": eventType,
				"jti":   claims.JTI,
			})
			out.IgnoredEvents = append(out.IgnoredEvents, eventType)
		}
	}
	return out, nil
}

func (r *Receiver) normalizeSubject(p EventPayload) (iss, sub string, ok bool) {
	switch p.Subject.Format {
	case "iss_sub", "":
		// "" tolerated for transmitters that omit format when iss+sub
		// are both present. Strict spec compliance would require
		// format="iss_sub" — this is permissive forward-compat.
		if p.Subject.Iss == "" || p.Subject.Sub == "" {
			return "", "", false
		}
		return p.Subject.Iss, p.Subject.Sub, true
	}
	return "", "", false
}

func (r *Receiver) deriveReason(eventType string, p EventPayload) string {
	if v, ok := p.ReasonAdmin["en"]; ok && v != "" {
		return v
	}
	switch eventType {
	case EventSessionRevoked:
		return "caep_session_revoked"
	case EventCredentialChange:
		return "caep_credential_change"
	case EventAccountDisabled:
		return "caep_account_disabled"
	case EventAccountPurged:
		return "caep_account_purged"
	case EventAccountCredentialChangeRequired:
		return "caep_credential_change_required"
	}
	return "caep_event"
}

func (r *Receiver) emit(eventType string, fields map[string]any) {
	if r.cfg.Audit == nil {
		return
	}
	r.cfg.Audit.Emit(eventType, fields)
}

func (r *Receiver) permittedAlgs() []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, 0, len(r.allowedAlgsSet))
	for a := range r.allowedAlgsSet {
		out = append(out, a)
	}
	return out
}

