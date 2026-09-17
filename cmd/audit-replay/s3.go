// SPDX-License-Identifier: AGPL-3.0-or-later

// s3.go — Phase 8.c.5 WORM bucket reads for audit-replay.
//
// Adds the `s3://[endpoint/]bucket/key` URL scheme to the file argument
// list. When detected, the URL is fetched via the MinIO Go SDK and the
// object body is streamed to the existing NDJSON parser. Designed for
// the audit-archive MinIO tenant (internal engineering notes:
// "WORM audit retention = 7 years, dedicated audit-archive MinIO with
// object-lock governance").
//
// URL forms supported:
//   - s3://bucket/key                   — uses default endpoint from env
//   - s3://endpoint:port/bucket/key     — endpoint override (rare;
//                                          useful for ad-hoc reads from
//                                          a non-default MinIO instance)
//
// Credentials lookup order (first non-empty wins):
//  1. AUDIT_REPLAY_S3_ACCESS_KEY / AUDIT_REPLAY_S3_SECRET_KEY
//  2. AWS_ACCESS_KEY_ID         / AWS_SECRET_ACCESS_KEY
//
// Default endpoint when the URL doesn't carry one: env
// AUDIT_REPLAY_S3_ENDPOINT, else the in-cluster Service
// `audit-archive-hl.minio-audit-archive.svc.cluster.local:9000`
// (the per-bucket HL Service hexxlock uses for in-cluster tenant
// access). Operators running the CLI from outside the cluster MUST set
// AUDIT_REPLAY_S3_ENDPOINT to a reachable address.
//
// Insecure default: HTTP. MinIO inside the cluster terminates HTTPS at
// the operator/edge tier (Linkerd mTLS is the transport boundary for
// Pod→Pod, not the registry itself). Operators reading from outside
// the cluster who need HTTPS can set AUDIT_REPLAY_S3_INSECURE=false.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// isS3URL returns true for paths beginning with "s3://".
func isS3URL(path string) bool {
	return strings.HasPrefix(path, "s3://")
}

// parseS3URL splits the URL into (endpoint, bucket, key).
//
// The form "s3://bucket/key" returns endpoint = "" (use env default).
// The form "s3://host:port/bucket/key" returns endpoint = "host:port".
// We distinguish via the presence of ":" in the first path segment.
func parseS3URL(rawURL string) (endpoint, bucket, key string, err error) {
	if !isS3URL(rawURL) {
		return "", "", "", fmt.Errorf("not an s3 URL: %s", rawURL)
	}
	rest := strings.TrimPrefix(rawURL, "s3://")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("s3 URL missing key: %s", rawURL)
	}
	// `parts[0]` is either a bucket name (no colon) or a host:port.
	// Bucket names cannot contain ":" per AWS S3 + MinIO naming rules
	// (RFC 1123 + 3-63 lowercase chars + dots/hyphens), so a ":" in
	// parts[0] unambiguously means an endpoint override.
	if strings.Contains(parts[0], ":") {
		if len(parts) < 3 {
			return "", "", "", fmt.Errorf("s3 URL with endpoint override missing bucket+key: %s", rawURL)
		}
		endpoint = parts[0]
		bucket = parts[1]
		key = parts[2]
	} else {
		bucket = parts[0]
		key = strings.Join(parts[1:], "/")
	}
	if bucket == "" || key == "" {
		return "", "", "", fmt.Errorf("s3 URL bucket and key required: %s", rawURL)
	}
	return endpoint, bucket, key, nil
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// openS3 returns an io.ReadCloser for the object at the URL.
//
// Failure modes (all wrapped):
//   - URL parse error
//   - missing credentials
//   - MinIO client init
//   - object GetObject network/auth error (only surfaces on first Read
//     in minio-go v7; we issue a one-byte probe via Stat to surface
//     auth/404 errors here at openS3 time)
func openS3(rawURL string) (io.ReadCloser, error) {
	endpoint, bucket, key, err := parseS3URL(rawURL)
	if err != nil {
		return nil, err
	}

	if endpoint == "" {
		endpoint = firstNonEmpty(
			os.Getenv("AUDIT_REPLAY_S3_ENDPOINT"),
			"audit-archive-hl.minio-audit-archive.svc.cluster.local:9000",
		)
	}

	accessKey := firstNonEmpty(
		os.Getenv("AUDIT_REPLAY_S3_ACCESS_KEY"),
		os.Getenv("AWS_ACCESS_KEY_ID"),
	)
	secretKey := firstNonEmpty(
		os.Getenv("AUDIT_REPLAY_S3_SECRET_KEY"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
	)
	if accessKey == "" || secretKey == "" {
		return nil, errors.New("s3 read requires AUDIT_REPLAY_S3_ACCESS_KEY/SECRET_KEY (or AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY)")
	}

	// Insecure (HTTP) is the default for in-cluster MinIO. Set
	// AUDIT_REPLAY_S3_INSECURE=false to require HTTPS (e.g. for
	// out-of-cluster reads).
	useSSL := strings.EqualFold(os.Getenv("AUDIT_REPLAY_S3_INSECURE"), "false")

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("minio client init: %w", err)
	}

	// Probe with StatObject to surface auth + 404 errors at open time
	// rather than mid-stream. The object body is then streamed via
	// GetObject (which is lazy in minio-go v7; calling Stat() after
	// GetObject opens the connection, but we already stat-probed).
	ctx := context.Background()
	if _, err := client.StatObject(ctx, bucket, key, minio.StatObjectOptions{}); err != nil {
		return nil, fmt.Errorf("stat s3://%s/%s: %w", bucket, key, err)
	}

	obj, err := client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("get s3://%s/%s: %w", bucket, key, err)
	}
	return obj, nil
}
