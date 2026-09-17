// SPDX-License-Identifier: AGPL-3.0-or-later

package conversion

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/hexxlock/talon/api/v1alpha1"
	v1beta1 "github.com/hexxlock/talon/api/v1beta1"
)

const (
	v1alpha1API = "gateway.talon.hexxlock.com/v1alpha1"
	v1beta1API  = "gateway.talon.hexxlock.com/v1beta1"
)

func TestHandler_UpConvert_V1alpha1ToV1beta1(t *testing.T) {
	src := &v1alpha1.TalonRoute{
		TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1API, Kind: "TalonRoute"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-ops", Namespace: "monitoring",
		},
		Spec: v1alpha1.TalonRouteSpec{
			Host:        "internal.example.com",
			Upstream:    v1alpha1.Upstream{Service: "kube-prometheus-stack-prometheus", Port: 9090},
			Permission:  v1alpha1.PermissionViewer,
			MfaRequired: true,
			AuthMode:    "cookie",
		},
	}
	resp := postReview(t, []runtime.Object{src}, v1beta1API)

	if resp.Result.Status != "Success" {
		t.Fatalf("Result.Status: want Success, got %q (msg %q)", resp.Result.Status, resp.Result.Message)
	}
	if got := len(resp.ConvertedObjects); got != 1 {
		t.Fatalf("ConvertedObjects len: want 1, got %d", got)
	}

	var out v1beta1.TalonRoute
	if err := json.Unmarshal(resp.ConvertedObjects[0].Raw, &out); err != nil {
		t.Fatalf("decode converted: %v", err)
	}
	if out.APIVersion != v1beta1API {
		t.Errorf("apiVersion stamped: want %q, got %q", v1beta1API, out.APIVersion)
	}
	if out.Spec.Host != src.Spec.Host {
		t.Errorf("Host: want %q, got %q", src.Spec.Host, out.Spec.Host)
	}
	if string(out.Spec.DefaultPolicy.Permission) != string(src.Spec.Permission) {
		t.Errorf("DefaultPolicy.Permission: want %q, got %q",
			src.Spec.Permission, out.Spec.DefaultPolicy.Permission)
	}
	if !out.Spec.DefaultPolicy.MfaRequired {
		t.Errorf("DefaultPolicy.MfaRequired: want true, got false")
	}
}

func TestHandler_DownConvert_V1beta1ToV1alpha1_DropsPathRules(t *testing.T) {
	src := &v1beta1.TalonRoute{
		TypeMeta: metav1.TypeMeta{APIVersion: v1beta1API, Kind: "TalonRoute"},
		ObjectMeta: metav1.ObjectMeta{Name: "gitlab", Namespace: "monitoring"},
		Spec: v1beta1.TalonRouteSpec{
			Host: "github.com",
			Upstream: v1beta1.Upstream{Service: "gitlab", Port: 80},
			DefaultPolicy: v1beta1.Policy{
				AuthMode:   "cookie",
				Permission: v1beta1.PermissionViewer,
			},
			PathRules: []v1beta1.PathRule{
				{
					Name: "api-bearer",
					Match: v1beta1.PathRuleMatch{
						PathPrefix: []string{"/api/"},
					},
					Policy: v1beta1.Policy{
						AuthMode: "bearer_or_basic_with_credential_exchange",
					},
				},
			},
		},
	}
	resp := postReview(t, []runtime.Object{src}, v1alpha1API)
	if resp.Result.Status != "Success" {
		t.Fatalf("Result.Status: %q (msg %q)", resp.Result.Status, resp.Result.Message)
	}

	var out v1alpha1.TalonRoute
	if err := json.Unmarshal(resp.ConvertedObjects[0].Raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Spec.Host != "github.com" {
		t.Errorf("Host lost: %q", out.Spec.Host)
	}
	if out.Spec.AuthMode != "cookie" {
		t.Errorf("AuthMode (from DefaultPolicy): want cookie, got %q", out.Spec.AuthMode)
	}
	// PathRules are silently dropped — v1alpha1 has no such field.
	// Caller (controller reconciling v1alpha1) gets host-default
	// behaviour, never elevates to a deny. Documented in
	// api/v1beta1/conversion.go's ToV1alpha1Spec comment.
}

func TestHandler_IdentityPassthrough_NoConversion(t *testing.T) {
	// kube-apiserver may call us with desired == source as a sanity
	// check. Preserve the raw bytes exactly — no lossy JSON
	// round-trip.
	src := &v1alpha1.TalonRoute{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1API, Kind: "TalonRoute"},
		ObjectMeta: metav1.ObjectMeta{Name: "x"},
		Spec: v1alpha1.TalonRouteSpec{
			Host:     "x.hexxlock.com",
			Upstream: v1alpha1.Upstream{Service: "x", Port: 80},
		},
	}
	resp := postReview(t, []runtime.Object{src}, v1alpha1API)
	if resp.Result.Status != "Success" {
		t.Fatalf("Status: %q (%s)", resp.Result.Status, resp.Result.Message)
	}
	// The returned bytes should still be valid JSON describing the
	// same logical CR.
	var out v1alpha1.TalonRoute
	if err := json.Unmarshal(resp.ConvertedObjects[0].Raw, &out); err != nil {
		t.Fatalf("identity passthrough: decode: %v", err)
	}
	if out.Spec.Host != "x.hexxlock.com" {
		t.Errorf("identity passthrough: lost Host; got %q", out.Spec.Host)
	}
}

func TestHandler_UnsupportedVersion_Failure(t *testing.T) {
	// A CR with an unknown apiVersion should fail per-object without
	// poisoning the entire ConversionReview.
	bad := json.RawMessage(`{"apiVersion":"gateway.talon.hexxlock.com/v999unknown","kind":"TalonRoute","metadata":{"name":"x"}}`)
	review := apiextensionsv1.ConversionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "apiextensions.k8s.io/v1", Kind: "ConversionReview"},
		Request: &apiextensionsv1.ConversionRequest{
			UID:               "test-uid",
			DesiredAPIVersion: v1beta1API,
			Objects:           []runtime.RawExtension{{Raw: bad}},
		},
	}
	got := postReviewRaw(t, review)
	if got.Response.Result.Status != "Failure" {
		t.Errorf("unsupported version: want Failure, got %q", got.Response.Result.Status)
	}
	if !strings.Contains(got.Response.Result.Message, "unsupported conversion") {
		t.Errorf("error message: want 'unsupported conversion', got %q", got.Response.Result.Message)
	}
}

func TestHandler_RejectsGET(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: want 405, got %d", resp.StatusCode)
	}
}

func TestHandler_RejectsMalformedBody(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", bytes.NewBufferString("not json"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed body: want 400, got %d", resp.StatusCode)
	}
}

func TestHandler_PreservesUID(t *testing.T) {
	src := &v1alpha1.TalonRoute{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1API, Kind: "TalonRoute"},
		ObjectMeta: metav1.ObjectMeta{Name: "x"},
		Spec:       v1alpha1.TalonRouteSpec{Host: "x", Upstream: v1alpha1.Upstream{Service: "x", Port: 80}},
	}
	review := apiextensionsv1.ConversionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "apiextensions.k8s.io/v1", Kind: "ConversionReview"},
		Request: &apiextensionsv1.ConversionRequest{
			UID:               "unique-uid-12345",
			DesiredAPIVersion: v1beta1API,
			Objects:           []runtime.RawExtension{{Object: src}},
		},
	}
	got := postReviewRaw(t, review)
	if got.Response.UID != "unique-uid-12345" {
		t.Errorf("UID mirror: want unique-uid-12345, got %q", got.Response.UID)
	}
}

// --- test helpers ----------------------------------------------------

func postReview(t *testing.T, objs []runtime.Object, desired string) *apiextensionsv1.ConversionResponse {
	t.Helper()
	rawObjs := make([]runtime.RawExtension, 0, len(objs))
	for _, o := range objs {
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatalf("marshal obj: %v", err)
		}
		rawObjs = append(rawObjs, runtime.RawExtension{Raw: b})
	}
	review := apiextensionsv1.ConversionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "apiextensions.k8s.io/v1", Kind: "ConversionReview"},
		Request: &apiextensionsv1.ConversionRequest{
			UID:               "test-uid",
			DesiredAPIVersion: desired,
			Objects:           rawObjs,
		},
	}
	out := postReviewRaw(t, review)
	return out.Response
}

func postReviewRaw(t *testing.T, in apiextensionsv1.ConversionReview) *apiextensionsv1.ConversionReview {
	t.Helper()
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal review: %v", err)
	}
	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", resp.StatusCode)
	}
	respBody, _ := ioReadAll(resp.Body)
	var out apiextensionsv1.ConversionReview
	if err := json.Unmarshal(respBody, &out); err != nil {
		t.Fatalf("decode response: %v (body %q)", err, respBody)
	}
	return &out
}

// ioReadAll trivially wraps io.ReadAll to keep the test-file import
// list small (test scaffolding only).
func ioReadAll(r interface{ Read(p []byte) (n int, err error) }) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 1024)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}
