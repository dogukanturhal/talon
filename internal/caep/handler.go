// SPDX-License-Identifier: AGPL-3.0-or-later

package caep

import (
	"errors"
	"io"
	"net/http"
)

// HTTPHandler returns the POST /caep/events handler. Wire at the
// auth host's mux (typically https://internal.example.com/caep/events).
//
// Per RFC 8935 Push Delivery:
//
//	Content-Type: application/secevent+jwt
//	body = <compact-JWS-of-SET>
//	response = 202 Accepted (on success) | 400 (parse) | 401 (sig/aud)
//	         | 429 (replay) | 5xx (internal)
//
// The handler is deliberately strict on Content-Type — a missing or
// wrong type returns 415; this prevents accidental cross-API misuse.
func HTTPHandler(r *Receiver) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ct := req.Header.Get("Content-Type")
		// Accept both application/secevent+jwt (RFC 8935) and
		// application/jwt (some transmitters use the looser type).
		// Reject everything else.
		switch ct {
		case "application/secevent+jwt", "application/jwt":
			// ok
		default:
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, 64<<10)) // 64KiB cap
		if err != nil {
			http.Error(w, "body read", http.StatusBadRequest)
			return
		}
		setJWT := string(body)

		_, err = r.ProcessSET(req.Context(), setJWT)
		if err == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		// Map error class → status code. Body deliberately minimal —
		// SET transmitters are machine clients; the spec doesn't
		// require descriptive bodies.
		switch {
		case errors.Is(err, ErrParse), errors.Is(err, ErrEmptyEvents), errors.Is(err, ErrUnknownSubjectFmt):
			http.Error(w, "bad request", http.StatusBadRequest)
		case errors.Is(err, ErrSignature), errors.Is(err, ErrIssuerMismatch), errors.Is(err, ErrAudienceMismatch):
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case errors.Is(err, ErrTooOld):
			http.Error(w, "stale set", http.StatusBadRequest)
		case errors.Is(err, ErrReplay):
			// 429 with no Retry-After — the transmitter shouldn't
			// retry a SET it already delivered. Some RFC 8935
			// references suggest 200 for idempotent duplicates; we
			// opt for 429 because that's a clearer SIEM signal.
			http.Error(w, "duplicate set", http.StatusTooManyRequests)
		default:
			http.Error(w, "internal", http.StatusInternalServerError)
		}
	}
}
