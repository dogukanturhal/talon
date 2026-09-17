// SPDX-License-Identifier: AGPL-3.0-or-later

package posturesigner

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestHeartbeatRequest_Validate(t *testing.T) {
	validNonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	now := time.Now()

	tests := []struct {
		name    string
		req     HeartbeatRequest
		now     time.Time
		wantErr string // non-empty → expect error containing this string
	}{
		{
			name: "valid TIER_CORP",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      validNonce,
				IAT:        now.Unix(),
				Compliance: map[string]any{"disk_encrypted": true},
			},
			now: now,
		},
		{
			name: "valid TIER_BYOD with empty compliance",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierBYOD,
				Nonce:      validNonce,
				IAT:        now.Unix(),
				Compliance: map[string]any{},
			},
			now: now,
		},
		{
			name: "invalid UUID - not a UUID",
			req: HeartbeatRequest{
				DeviceUUID: "not-a-uuid",
				Tier:       TierCorp,
				Nonce:      validNonce,
				IAT:        now.Unix(),
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "device_uuid",
		},
		{
			name: "invalid UUID - v1",
			req: HeartbeatRequest{
				// UUIDv1 (time-based) — must be rejected; only v4 allowed
				DeviceUUID: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
				Tier:       TierCorp,
				Nonce:      validNonce,
				IAT:        now.Unix(),
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "device_uuid",
		},
		{
			name: "unknown tier",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       "TIER_ADMIN",
				Nonce:      validNonce,
				IAT:        now.Unix(),
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "tier",
		},
		{
			name: "empty nonce",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      "",
				IAT:        now.Unix(),
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "nonce",
		},
		{
			name: "nonce wrong length - 16 bytes",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
				IAT:        now.Unix(),
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "nonce",
		},
		{
			name: "nonce not base64url",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      "!!!not-base64!!!",
				IAT:        now.Unix(),
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "nonce",
		},
		{
			name: "zero iat",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      validNonce,
				IAT:        0,
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "iat",
		},
		{
			name: "iat too far in past (32s — beyond tolerance+truncation-grace)",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      validNonce,
				IAT:        now.Add(-32 * time.Second).Unix(),
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "iat",
		},
		{
			name: "iat too far in future (32s — beyond tolerance+truncation-grace)",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      validNonce,
				IAT:        now.Add(32 * time.Second).Unix(),
				Compliance: map[string]any{},
			},
			now:     now,
			wantErr: "iat",
		},
		{
			name: "iat at tolerance boundary (exactly 30s in past) — accepted",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      validNonce,
				IAT:        now.Add(-30 * time.Second).Unix(),
				Compliance: map[string]any{},
			},
			now: now,
		},
		{
			name: "nil compliance",
			req: HeartbeatRequest{
				DeviceUUID: validUUID,
				Tier:       TierCorp,
				Nonce:      validNonce,
				IAT:        now.Unix(),
				Compliance: nil,
			},
			now:     now,
			wantErr: "compliance",
		},
		{
			name: "multiple errors reported together",
			req: HeartbeatRequest{
				DeviceUUID: "bad",
				Tier:       "WRONG",
				Nonce:      "",
				IAT:        0,
				Compliance: nil,
			},
			now:     now,
			wantErr: "device_uuid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate(tc.now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}
