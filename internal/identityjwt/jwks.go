// SPDX-License-Identifier: AGPL-3.0-or-later

package identityjwt

import (
	"encoding/json"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

// JWKSHandler returns an http.Handler that publishes the signer's
// public key as an RFC 7517 JSON Web Key Set. Verifiers (Falcon-ID,
// the @hexxlock/falcon-id-client SDK, downstream apps consuming the
// signed Bearer pattern) fetch this endpoint and cache the keys.
//
// Cache-Control is set to `public, max-age=300` — 5 minutes is the
// industry default (Cloudflare Access publishes the same TTL, Google
// IAP uses 300s as well). Verifier libraries (jose's
// createRemoteJWKSet, jwt-go's cached keyfunc) honour this for free.
//
// Multi-key rotation: when the operator has populated
// AddPreviousPublicKeyFromPEM(...) on the signer (typically via the
// TALON_IAP_PREVIOUS_SIGNING_KEY_PEM env var), this handler publishes
// the active key AND every retired key in one JWKS document. Verifiers
// match on `kid`, so JWTs signed by either key are accepted during the
// overlap window. Matches Cloudflare Access's N+1 rotation pattern and
// Google IAP's daily-rotation model (multiple kids concurrently valid).
//
// Rotation runbook:
//
//  1. Write the NEW private key to Vault `key`; copy the OLD key to
//     `key_previous` in the same secret (or to a sibling secret).
//  2. Roll Talon. The new key signs all fresh JWTs; the old key is
//     published-only and verifies anything still in flight.
//  3. After the JWT lifetime (60s) + JWKS cache TTL (300s) ≈ 6
//     minutes, the old key has no outstanding JWTs; remove
//     `key_previous` from Vault and roll once more to drop it from
//     JWKS.
func JWKSHandler(signer *Signer) http.Handler {
	if signer == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "iap identity jwt signing not configured", http.StatusServiceUnavailable)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pub := signer.PublicKey()
		prev := signer.PreviousPublicKeys()
		keys := make([]jose.JSONWebKey, 0, 1+len(prev))
		keys = append(keys, jose.JSONWebKey{
			Key:       &pub,
			KeyID:     signer.Kid(),
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
		for _, rk := range prev {
			pub := rk.PublicKey
			keys = append(keys, jose.JSONWebKey{
				Key:       &pub,
				KeyID:     rk.Kid,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			})
		}
		set := jose.JSONWebKeySet{Keys: keys}
		body, err := json.Marshal(set)
		if err != nil {
			http.Error(w, "jwks marshal failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}
