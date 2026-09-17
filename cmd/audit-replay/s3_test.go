// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func TestParseS3URL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		in             string
		wantEndpoint   string
		wantBucket     string
		wantKey        string
		wantErrSubstr  string
	}{
		{
			name:         "bucket+key only",
			in:           "s3://audit-archive/2026-06-09/talon-pod-7d.ndjson",
			wantEndpoint: "",
			wantBucket:   "audit-archive",
			wantKey:      "2026-06-09/talon-pod-7d.ndjson",
		},
		{
			name:         "deep prefix",
			in:           "s3://audit-archive/year=2026/month=06/day=09/talon-pod-7d.ndjson",
			wantEndpoint: "",
			wantBucket:   "audit-archive",
			wantKey:      "year=2026/month=06/day=09/talon-pod-7d.ndjson",
		},
		{
			name:         "endpoint override host:port",
			in:           "s3://minio.example.com:9000/audit-archive/foo.ndjson",
			wantEndpoint: "minio.example.com:9000",
			wantBucket:   "audit-archive",
			wantKey:      "foo.ndjson",
		},
		{
			name:          "missing key",
			in:            "s3://audit-archive",
			wantErrSubstr: "missing key",
		},
		{
			name:          "missing bucket after endpoint",
			in:            "s3://host:9000/",
			wantErrSubstr: "missing bucket",
		},
		{
			name:          "not an s3 url",
			in:            "file:///tmp/foo",
			wantErrSubstr: "not an s3 URL",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ep, bucket, key, err := parseS3URL(tc.in)
			if tc.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tc.wantErrSubstr)
				}
				if !containsString(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("want error containing %q, got %q", tc.wantErrSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ep != tc.wantEndpoint {
				t.Errorf("endpoint: want %q, got %q", tc.wantEndpoint, ep)
			}
			if bucket != tc.wantBucket {
				t.Errorf("bucket: want %q, got %q", tc.wantBucket, bucket)
			}
			if key != tc.wantKey {
				t.Errorf("key: want %q, got %q", tc.wantKey, key)
			}
		})
	}
}

func TestIsS3URL(t *testing.T) {
	t.Parallel()
	if !isS3URL("s3://bucket/k") {
		t.Errorf("s3:// not recognised")
	}
	if isS3URL("/tmp/f") {
		t.Errorf("file path falsely recognised as s3 URL")
	}
	if isS3URL("-") {
		t.Errorf("stdin sentinel falsely recognised as s3 URL")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()
	if got := firstNonEmpty("", "", "a", "b"); got != "a" {
		t.Errorf("first non-empty: want a, got %q", got)
	}
	if got := firstNonEmpty("", "", ""); got != "" {
		t.Errorf("all empty: want empty, got %q", got)
	}
}

func containsString(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
