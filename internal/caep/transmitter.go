// SPDX-License-Identifier: AGPL-3.0-or-later

package caep

// transmitter.go — CAEP 1.0 TRANSMITTER (ADR 0043). The counterpart to
// receiver.go: builds + signs + push-delivers Security Event Tokens to a
// receiver's /caep/events endpoint (RFC 8935). posture-signer uses this to
// emit session-revoked + device-compliance-change events; Talon's own
// receiver (this same package) verifies + dispatches them.
//
// Both halves share the SET types in types.go, so a SET this transmitter
// builds is by construction wire-compatible with what the receiver parses.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Signer signs the SET envelope into a compact JWS (header.payload.sig).
// posture-signer implements this with its Vault Transit RS256 key
// (typ=secevent+jwt); tests use a fake. Kept narrow so the transmitter
// has no Vault dependency of its own.
type Signer interface {
	SignSET(ctx context.Context, claims SETClaims) (compactJWS string, err error)
}

// TransmitterConfig configures who the SETs are from/about/to.
type TransmitterConfig struct {
	// SetIssuer is the SET-envelope `iss` — the TRANSMITTER identity
	// (posture-signer, e.g. https://posture.example.com). The receiver
	// verifies the signature against this issuer's JWKS.
	SetIssuer string
	// SubjectIssuer is the event `subject.iss` — the user-session OWNER
	// the receiver keys RevokeBySubject on (Falcon-ID, e.g.
	// https://id.example.com). Distinct from SetIssuer on purpose.
	SubjectIssuer string
	// Audience is the SET `aud` (the receiver's auth host).
	Audience string
	// ReceiverURL is the push-delivery target (Talon /caep/events).
	ReceiverURL string
}

// Transmitter builds, signs, and pushes CAEP SETs.
type Transmitter struct {
	cfg    TransmitterConfig
	signer Signer
	hc     *http.Client
	now    func() time.Time
	newJTI func() string
}

// NewTransmitter constructs a Transmitter. signer must be non-nil.
func NewTransmitter(cfg TransmitterConfig, signer Signer) (*Transmitter, error) {
	if signer == nil {
		return nil, fmt.Errorf("caep: transmitter signer is required")
	}
	if cfg.SetIssuer == "" || cfg.Audience == "" || cfg.ReceiverURL == "" {
		return nil, fmt.Errorf("caep: transmitter SetIssuer, Audience, ReceiverURL are required")
	}
	if cfg.SubjectIssuer == "" {
		cfg.SubjectIssuer = cfg.SetIssuer
	}
	return &Transmitter{
		cfg:    cfg,
		signer: signer,
		hc:     &http.Client{Timeout: 10 * time.Second},
		now:    time.Now,
		newJTI: uuid.NewString,
	}, nil
}

// userSubject builds the iss_sub subject the receiver dispatches on.
func (t *Transmitter) userSubject(userSub string) Subject {
	return Subject{Format: "iss_sub", Iss: t.cfg.SubjectIssuer, Sub: userSub}
}

func (t *Transmitter) envelope(eventType string, ev EventPayload) SETClaims {
	now := t.now().Unix()
	ev.EventTimestamp = now
	return SETClaims{
		Iss:    t.cfg.SetIssuer,
		Aud:    audienceField{t.cfg.Audience},
		IAT:    now,
		JTI:    t.newJTI(),
		Events: map[string]EventPayload{eventType: ev},
	}
}

// BuildSessionRevoked emits the actionable event: the device/user is
// de-provisioned → the receiver revokes every session for (SubjectIssuer,
// userSub). reason is a short admin-facing explanation.
func (t *Transmitter) BuildSessionRevoked(userSub, reason string) SETClaims {
	ev := EventPayload{
		Subject:          t.userSubject(userSub),
		InitiatingEntity: "policy",
	}
	if reason != "" {
		ev.ReasonAdmin = LangMap{"en": reason}
	}
	return t.envelope(EventSessionRevoked, ev)
}

// BuildDeviceComplianceChange emits an audit signal that a device crossed
// the compliance boundary. compliant=false means it fell OUT of compliance.
// The device UUID rides in reason_admin (the receiver audits; EventPayload
// has no dedicated device field) and the status in current_level.
func (t *Transmitter) BuildDeviceComplianceChange(userSub, deviceUUID string, compliant bool) SETClaims {
	status := "compliant"
	if !compliant {
		status = "not-compliant"
	}
	ev := EventPayload{
		Subject:          t.userSubject(userSub),
		InitiatingEntity: "policy",
		CurrentLevel:     status,
		ReasonAdmin:      LangMap{"en": fmt.Sprintf("device %s is %s", deviceUUID, status)},
	}
	return t.envelope(EventDeviceComplianceChange, ev)
}

// Emit signs the SET and push-delivers it to the receiver. Returns nil on
// a 2xx (202 Accepted is the spec success); any other status or transport
// failure is an error the caller logs (non-fatal — losing one event must
// not break the heartbeat path).
func (t *Transmitter) Emit(ctx context.Context, claims SETClaims) error {
	compact, err := t.signer.SignSET(ctx, claims)
	if err != nil {
		return fmt.Errorf("caep: sign SET: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.ReceiverURL, bytes.NewReader([]byte(compact)))
	if err != nil {
		return fmt.Errorf("caep: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	resp, err := t.hc.Do(req)
	if err != nil {
		return fmt.Errorf("caep: deliver SET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("caep: receiver returned HTTP %d: %s", resp.StatusCode, body)
	}
	return nil
}

// marshalSET is a small helper used by tests + the signer adapter to get
// the canonical JSON of the envelope.
func marshalSET(claims SETClaims) ([]byte, error) { return json.Marshal(claims) }
