// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// embeddedSchema is the canonical talon.audit.v1 JSON Schema embedded
// at build time via go:embed. Operators can override by passing a
// path with `--validate-schema /path/to/custom.json`; the empty-arg
// form `--validate-schema=""` is interpreted as `--validate-schema
// docs/architecture/0041-schema.json` (the embedded copy).
//
// Why embed: tier-1 contract — the validator must work without
// runtime filesystem dependencies, so an air-gapped reviewer
// auditing a 7-year-old WORM archive can verify schema conformance
// using only the binary (no separate file fetch required).
//
// The canonical schema lives at docs/architecture/0041-schema.json
// (authoritative). A build-time copy in cmd/audit-replay/schemas/
// is what go:embed picks up — Go's embed directive does not accept
// `../` paths. The Makefile (and a CI gate added in this MR — see
// commit body) keeps the two copies in sync by failing the build
// if they drift.
//
//go:embed schemas/audit-record.json
var embeddedSchema []byte

// schemaValidator wraps a compiled JSON Schema 2020-12 validator and
// applies it to each NDJSON line. Designed to be cheap to call per-
// record — the schema is compiled exactly once at startup, every
// subsequent Validate is a stateless tree walk.
//
// Used by the --validate-schema mode (ADR 0041 §8.c.3). Operates
// alongside --print + --check-gaps + --ztna-decision-stats. UNLIKE
// --reconstruct-session, schema validation is a side-effect: each
// line's status (valid or list of violations) is reported on
// stderr, the line itself still flows through the other modes
// untouched.
//
// Violation reporting strategy:
//   - In NON-strict mode: violations emit a WARN line to stderr with
//     line number + field path + reason, but the line continues to
//     pass through downstream emitters (--print etc.). The summary
//     at exit reports total violation count.
//   - In strict mode (--strict): the FIRST violation causes
//     audit-replay to exit nonzero. Use this in CI / pre-archive
//     gates to enforce schema conformance before WORM commit.
//
// Cardinality: schema validation is O(field-count × tree-depth) per
// record. For talon.audit.v1's ~17-field shape, validation overhead
// is < 50µs per record on typical NDJSON (sub-ms even at million-
// records/min throughput).
type schemaValidator struct {
	schema     *jsonschema.Schema
	violations int
	strict     bool
}

// newSchemaValidator compiles the named schema. Pass an empty path to
// use the embedded canonical talon.audit.v1 schema; pass a file path
// to use an operator-supplied override.
func newSchemaValidator(path string, strict bool) (*schemaValidator, error) {
	c := jsonschema.NewCompiler()

	var source []byte
	var resourceID string
	if path == "" {
		source = embeddedSchema
		resourceID = "https://talon.hexxlock.com/schemas/0041-audit-record.json"
	} else {
		var err error
		// File path — let the compiler read directly. v6 supports
		// AddResource for embedded sources.
		schema, err := c.Compile(path)
		if err != nil {
			return nil, fmt.Errorf("compile schema %q: %w", path, err)
		}
		return &schemaValidator{schema: schema, strict: strict}, nil
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
	if err != nil {
		return nil, fmt.Errorf("decode embedded schema: %w", err)
	}
	if err := c.AddResource(resourceID, doc); err != nil {
		return nil, fmt.Errorf("add embedded schema resource: %w", err)
	}
	schema, err := c.Compile(resourceID)
	if err != nil {
		return nil, fmt.Errorf("compile embedded schema: %w", err)
	}
	return &schemaValidator{schema: schema, strict: strict}, nil
}

// validate runs the schema against ONE NDJSON line. Returns:
//   - violationErr: non-nil if the record violates the schema (one
//     concatenated message; jsonschema's ValidationError carries all
//     leaf violations as a tree, which we flatten for stderr).
//   - protoErr: non-nil if the line couldn't be JSON-decoded at all
//     (this is distinct from a schema violation — a malformed line
//     is treated by the surrounding stream loop the same way an
//     non-JSON line is: WARN-and-skip outside strict, FATAL inside).
func (v *schemaValidator) validate(line []byte) (violationErr error, protoErr error) {
	if v == nil || v.schema == nil {
		return nil, nil
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber() // preserves numeric precision for the schema validator
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	if err := v.schema.Validate(doc); err != nil {
		v.violations++
		// jsonschema/v6 returns *ValidationError tree; format compactly.
		return fmt.Errorf("schema violation: %s", flattenValidationError(err)), nil
	}
	return nil, nil
}

// flattenValidationError converts the (sometimes deep) jsonschema
// ValidationError tree to a single-line stderr-friendly summary. We
// keep the leaf message + the field path; the tree's higher-level
// "doesn't satisfy schema X" wrappers are noise for operators.
func flattenValidationError(err error) string {
	if err == nil {
		return ""
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return err.Error()
	}
	// The leaf-most causes have the most actionable detail; ascend
	// the tree only once to keep output bounded.
	if len(ve.Causes) == 0 {
		return ve.Error()
	}
	parts := make([]string, 0, len(ve.Causes))
	for _, c := range ve.Causes {
		parts = append(parts, c.Error())
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " ; "
		}
		out += p
	}
	return out
}

// report writes a stderr summary at the end of the run.
func (v *schemaValidator) report(w io.Writer) {
	if v == nil {
		return
	}
	if v.violations == 0 {
		_, _ = fmt.Fprintln(w, "schema: 0 violations")
		return
	}
	_, _ = fmt.Fprintf(w, "schema: %d violations\n", v.violations)
}
