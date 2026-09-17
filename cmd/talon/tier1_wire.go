// SPDX-License-Identifier: AGPL-3.0-or-later

// tier1_wire.go — runtime helpers for the Phase-7 tier-1 IAP modules
// (CAEP receiver, device-posture verifier). Kept separate from main.go
// so the boot path stays focused on lifecycle wiring; this file
// provides the small adapters that bridge each new module's interface
// to the existing Talon dependency graph.
//
// All adapters in this file are intentionally thin — they hold no
// state beyond what each interface contract demands. Production-grade
// JWKS rotation lives in internal/svctoken (already battle-tested
// against Falcon-ID); these adapters delegate signing-key resolution
// to a simple fetch-with-cache (refresh every 5min, retain stale on
// fetch failure) that mirrors the same posture.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/dogukanturhal/talon/internal/audit"
	"github.com/dogukanturhal/talon/internal/caep"
	"github.com/dogukanturhal/talon/internal/dpop"
	"github.com/dogukanturhal/talon/internal/session"
)

// caepAuditAdapter bridges caep.AuditEmitter (Emit(eventType string,
// fields map[string]any)) to the Talon audit.Emitter
// (Emit(context.Context, audit.Record)). The conversion keeps each
// CAEP event type as a distinct audit.Event so SIEM rules can match
// on the discriminator field; the rest of the fields drop into the
// audit Record's existing structured shape where there's a 1:1
// mapping (sub, reason, jti) and accumulate in the catch-all
// AdditionalFields map otherwise.
type caepAuditAdapter struct {
	emitter *audit.Emitter
}

func (a *caepAuditAdapter) Emit(eventType string, fields map[string]any) {
	if a == nil || a.emitter == nil {
		return
	}
	rec := audit.Record{
		Event:     audit.Event(eventType),
		Timestamp: time.Now().UTC(),
	}
	if v, ok := fields["sub"].(string); ok {
		rec.Sub = v
	}
	if v, ok := fields["iss"].(string); ok {
		rec.Issuer = v
	}
	if v, ok := fields["reason"].(string); ok {
		rec.Reason = v
	}
	if v, ok := fields["jti"].(string); ok {
		rec.SessionID = v // CAEP jti is the closest match in the existing schema
	}
	a.emitter.Emit(context.Background(), rec)
}

// caepRevoker adapts session.Store's RevokeBySubject to caep.SubjectRevoker.
//
// Wiring: caep package emits one Revoke call per CAEP SET that names
// a subject (session-revoked, credential-change, account-disabled,
// account-purged, account-credential-change-required). The receiver
// passes (iss, sub, reason); our session store currently indexes by
// sub only — iss is captured advisory for future multi-OP setups.
type caepRevoker struct {
	store *session.Store
}

// RevokeBySubject implements caep.SubjectRevoker by delegating to the
// session store. Returns the count of sessions revoked + any error
// from Redis.
func (r *caepRevoker) RevokeBySubject(ctx context.Context, iss, sub, reason string) (int, error) {
	if r == nil || r.store == nil {
		return 0, errors.New("caepRevoker: store is nil")
	}
	return r.store.RevokeBySubject(ctx, iss, sub, reason)
}

// caepReplayCache returns a dpop.MemoryCache typed for SET jti replay.
// CAEP SETs are idempotent so duplicate processing is harmless, but
// per RFC 8935 the receiver SHOULD reject duplicates within the
// transmitter's retry window. 24h default cache TTL matches caep
// receiver's JTITTL.
func caepReplayCache() caep.ReplayCache {
	// dpop.MemoryCache implements SeenOrAdd, which matches
	// caep.ReplayCache's interface exactly.
	return dpop.NewMemoryCache(0)
}

// simpleJWKSResolver fetches a JWKS URL on first use and caches the
// keyset for `refresh` duration. On fetch failure it retains the
// stale keyset (fail-soft refresh) until the operator's monitoring
// surfaces the upstream JWKS unreachable condition; the cache hard-
// expires after `stale` so a long-term outage eventually closes.
//
// Implements caep.JWKSResolver (Keys takes only kid; iss is
// pre-bound by the URL passed at construction).
type simpleJWKSResolver struct {
	url string

	mu          sync.Mutex
	cached      *jose.JSONWebKeySet
	cachedAt    time.Time
	refresh     time.Duration
	stale       time.Duration
	httpClient  *http.Client
}

func newSimpleJWKSResolver(jwksURL string) *simpleJWKSResolver {
	return &simpleJWKSResolver{
		url:     jwksURL,
		refresh: 5 * time.Minute,
		stale:   1 * time.Hour,
		httpClient: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				// Talon-side CA bundle is the cluster default trust
				// store; Falcon-ID's TLS cert is issued by the
				// cluster's cert-manager root which is in the system
				// trust chain (chart wires it via Vault PKI).
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

// Keys implements caep.JWKSResolver. Returns the public-key materials
// matching kid (or, when kid is empty, all keys — for kid-less SETs).
func (r *simpleJWKSResolver) Keys(ctx context.Context, kid string) ([]any, error) {
	keys, err := r.fetch(ctx)
	if err != nil {
		return nil, err
	}
	if kid == "" {
		out := make([]any, 0, len(keys.Keys))
		for i := range keys.Keys {
			out = append(out, keys.Keys[i].Key)
		}
		return out, nil
	}
	out := []any{}
	for i := range keys.Keys {
		if keys.Keys[i].KeyID == kid {
			out = append(out, keys.Keys[i].Key)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("simpleJWKSResolver: no key matched kid %q", kid)
	}
	return out, nil
}

func (r *simpleJWKSResolver) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if r.cached != nil && now.Sub(r.cachedAt) < r.refresh {
		return r.cached, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		if r.cached != nil && now.Sub(r.cachedAt) < r.stale {
			return r.cached, nil
		}
		return nil, fmt.Errorf("simpleJWKSResolver: build request: %w", err)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		if r.cached != nil && now.Sub(r.cachedAt) < r.stale {
			return r.cached, nil
		}
		return nil, fmt.Errorf("simpleJWKSResolver: fetch %s: %w", r.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		if r.cached != nil && now.Sub(r.cachedAt) < r.stale {
			return r.cached, nil
		}
		return nil, fmt.Errorf("simpleJWKSResolver: %s returned %d", r.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10)) // 256KiB cap
	if err != nil {
		return nil, fmt.Errorf("simpleJWKSResolver: read body: %w", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("simpleJWKSResolver: decode JWKS: %w", err)
	}
	r.cached = &set
	r.cachedAt = now
	return r.cached, nil
}

// postureJWKSResolver is the multi-issuer variant of simpleJWKSResolver
// — posture.JWKSResolver takes (iss, kid). Each issuer maps to a
// distinct JWKS URL constructed by appending /.well-known/jwks.json
// to the issuer. Per ADR 0011 the posture-issuer trust chain is
// intentionally distinct from Falcon-ID; this resolver type makes
// that boundary explicit.
type postureJWKSResolver struct {
	mu      sync.Mutex
	clients map[string]*simpleJWKSResolver
}

// newPostureJWKSResolver maps each trusted issuer to a JWKS endpoint. By
// default that is `<iss>/.well-known/jwks.json`, but when jwksURLOverride is
// non-empty it is used for EVERY issuer — required when the issuer's public
// JWKS URL is unreachable from the Talon pod (the posture-signer's public
// issuer is Envoy device-cert-mTLS-gated; point the override at the in-cluster
// Service JWKS instead). The `iss` claim is still verified against the trusted
// set by the posture verifier; this only changes where the key is fetched.
func newPostureJWKSResolver(trustedIssuers []string, jwksURLOverride string) *postureJWKSResolver {
	r := &postureJWKSResolver{clients: map[string]*simpleJWKSResolver{}}
	for _, iss := range trustedIssuers {
		url := jwksURLOverride
		if url == "" {
			url = iss + "/.well-known/jwks.json"
		}
		r.clients[iss] = newSimpleJWKSResolver(url)
	}
	return r
}

// Keys implements posture.JWKSResolver.
func (r *postureJWKSResolver) Keys(ctx context.Context, iss, kid string) ([]any, error) {
	r.mu.Lock()
	client, ok := r.clients[iss]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("postureJWKSResolver: issuer %q not in trusted set", iss)
	}
	return client.Keys(ctx, kid)
}
