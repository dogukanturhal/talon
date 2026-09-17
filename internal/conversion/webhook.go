// SPDX-License-Identifier: AGPL-3.0-or-later

// Package conversion implements the CRD conversion webhook for the
// TalonRoute v1alpha1 ↔ v1beta1 conversion (Phase 6a.2). The
// kube-apiserver POSTs `apiextensions.k8s.io/v1.ConversionReview`
// requests to /convert whenever a client reads or writes a CR in a
// version different from the storage version.
//
// Why this exists
// ===============
// v1beta1 (talon!85) shipped the type system + hand-written
// conversion functions. v1alpha1 stays as storage version (no
// etcd migration). The conversion webhook handles up/down convert
// at admission so operators can author v1beta1 CRs even though
// they're stored as v1alpha1 internally. Phase 6a.2.
//
// Safety
// ======
// The webhook is the LOAD-BEARING admission gate — a misconfigured
// webhook breaks ALL TalonRoute reads and writes cluster-wide
// (api-server can't convert, returns 503-style errors to kubectl).
// Mitigations:
//
//  - Identity conversion (apiVersion == desiredAPIVersion) is a fast
//    passthrough. The webhook never has to error on the "no
//    conversion needed" path.
//  - Unrecognised versions return a per-object failure WITHOUT
//    poisoning the entire ConversionReview — kube-apiserver retries
//    and surfaces the error per resource, not cluster-wide.
//  - Rollback: `kubectl patch crd talonroutes.gateway.talon.hexxlock.
//    com --type=json -p='[{"op":"remove","path":"/spec/conversion"}]'`
//    removes the webhook strategy entirely; v1alpha1 stays served
//    + storage, v1beta1 reads start returning 415 errors but
//    v1alpha1 operations keep working.
//
// Wire format
// ===========
// Per `apiextensions.k8s.io/v1.ConversionReview`:
//
//   Request:  { uid, desiredAPIVersion, objects[] }
//   Response: { uid, result{status,message}, convertedObjects[] }
//
// Each object in objects[] is a runtime.RawExtension (JSON-encoded
// CR). For each, we peek at apiVersion, decode to the appropriate
// type, run the in-process conversion (api/v1beta1/conversion.go),
// re-marshal as the desiredAPIVersion shape.
package conversion

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"

	v1alpha1 "github.com/dogukanturhal/talon/api/v1alpha1"
	v1beta1 "github.com/dogukanturhal/talon/api/v1beta1"
)

// Handler returns the http.Handler that processes ConversionReview
// POSTs. Mount at /convert on the conversion-webhook server.
func Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		var review apiextensionsv1.ConversionReview
		if err := json.Unmarshal(body, &review); err != nil {
			http.Error(w, "decode review: "+err.Error(), http.StatusBadRequest)
			return
		}
		if review.Request == nil {
			http.Error(w, "missing review.Request", http.StatusBadRequest)
			return
		}

		// Build the response in-place. kube-apiserver expects the
		// same TypeMeta / UID on the way back.
		review.Response = convertObjects(review.Request)
		// Drop the request so the response payload is small. Some
		// older clients echo the request back; modern ones ignore.
		review.Request = nil

		out, err := json.Marshal(&review)
		if err != nil {
			http.Error(w, "encode review: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}
}

// convertObjects walks ConversionRequest.Objects and applies the
// in-process conversion to each. A per-object error sets
// Result.Status=Failure with a descriptive message; kube-apiserver
// retries per-resource so a single bad CR doesn't poison every
// other one in a List call.
func convertObjects(req *apiextensionsv1.ConversionRequest) *apiextensionsv1.ConversionResponse {
	resp := &apiextensionsv1.ConversionResponse{
		UID: req.UID,
	}
	out := make([]runtime.RawExtension, 0, len(req.Objects))
	for i, raw := range req.Objects {
		converted, err := convertOne(raw.Raw, req.DesiredAPIVersion)
		if err != nil {
			resp.Result.Status = "Failure"
			resp.Result.Message = fmt.Sprintf("convert object[%d]: %s", i, err.Error())
			return resp
		}
		out = append(out, runtime.RawExtension{Raw: converted})
	}
	resp.ConvertedObjects = out
	resp.Result.Status = "Success"
	return resp
}

// convertOne handles a single CR. Strategy:
//  1. Peek at apiVersion (cheap — single field).
//  2. If source == desired, passthrough (no decode/encode round-trip).
//  3. Otherwise, decode into the source type, call the in-process
//     conversion, re-marshal as the desired shape.
func convertOne(raw []byte, desired string) ([]byte, error) {
	var probe struct {
		APIVersion string `json:"apiVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("peek apiVersion: %w", err)
	}
	source := probe.APIVersion

	// Identity passthrough. Kube-apiserver may call us with
	// desired == source for sanity checks; preserve the raw bytes
	// exactly to avoid lossy JSON re-encoding.
	if source == desired {
		return raw, nil
	}

	switch {
	case source == v1alpha1.GroupVersion.String() && desired == v1beta1.GroupVersion.String():
		var src v1alpha1.TalonRoute
		if err := json.Unmarshal(raw, &src); err != nil {
			return nil, fmt.Errorf("decode v1alpha1: %w", err)
		}
		dst := v1beta1.FromV1alpha1(&src)
		return json.Marshal(dst)

	case source == v1beta1.GroupVersion.String() && desired == v1alpha1.GroupVersion.String():
		var src v1beta1.TalonRoute
		if err := json.Unmarshal(raw, &src); err != nil {
			return nil, fmt.Errorf("decode v1beta1: %w", err)
		}
		dst := v1beta1.ToV1alpha1(&src)
		return json.Marshal(dst)
	}

	return nil, fmt.Errorf("unsupported conversion %s → %s", source, desired)
}
