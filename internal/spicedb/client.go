// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spicedb is Talon's SpiceDB client + helpers. It verifies the
// required schema definitions are present in the live cluster schema
// at startup (EnsureSchema — read-only, see schemaZed's doc comment)
// and implements the per-request CheckPermission flow per ADR 0001
// §5.b + ADR 0003 §5.
package spicedb

import (
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	v1pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// schemaZed documents the SpiceDB definitions Talon requires
// (user/group/talon_route — ADR 0001 §5.b). It is READ-ONLY: it is
// NEVER passed to WriteSchema.
//
// an internal incident root-caused a production incident (2026-09-07/08) to THREE
// independent WriteSchema callers racing against the same global
// SpiceDB instance — this package's own EnsureSchema (called from
// every pod's startup via go:embed), Talon's separate PreSync hook,
// and falcon-id's PostSync hook — against SpiceDB's WriteSchema RPC,
// which REPLACES the entire schema rather than merging it. Whichever
// call landed last silently destroyed the other two writers'
// definitions; a routine HPA scale-up reverted a live 45-definition
// schema back to this file's original 3-definition copy, 1h29m45s
// after the correct schema had landed, with zero ArgoCD sync or CI
// pipeline activity involved. Full incident record on board row
// an internal incident.
//
// Fix: exactly one writer for this global resource. Talon's PreSync
// hook (deploy/helm/talon/templates/spicedb-seed-job.yaml) is deleted
// and this file is no longer given to WriteSchema — the dedicated
// `spicedb-schema` Argo CD Application (chart in
// hexxlock/falcon-id.git:deploy/helm/spicedb-schema, synced
// independently of both Talon and falcon-id) is now the cluster's
// ONLY WriteSchema caller. This copy is retained solely as the
// source of truth for EnsureSchema's startup verification below and
// MUST be kept in sync with the canonical copy at
// hexxlock/falcon-id.git:deploy/helm/spicedb-schema/files/spicedb.zed
// (a CI drift check between the two copies is a natural an internal incident
// follow-up, not yet implemented).
//
//go:embed schema.zed
var schemaZed string

// Schema returns the embedded schema source.
func Schema() string { return schemaZed }

// definitionRE extracts `definition <name> {` declarations from a
// schema source string. Whitespace-tolerant between the keyword, the
// name, and the opening brace, matching the extraction regex the
// spicedb-schema chart's self-verification Job uses on write.
var definitionRE = regexp.MustCompile(`definition\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{`)

// definitionNames returns the definition names declared in schema, in
// source order. Used at startup to compute the set of definitions
// Talon requires from the embedded schemaZed.
func definitionNames(schema string) []string {
	matches := definitionRE.FindAllStringSubmatch(schema, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
}

// hasDefinition reports whether liveSchema (as read back from
// SpiceDB's ReadSchema) declares the given definition name.
// Whitespace-tolerant: SpiceDB's own schema pretty-printer does not
// guarantee byte-identical formatting/spacing on read-back relative
// to whatever was originally written.
func hasDefinition(liveSchema, name string) bool {
	re := regexp.MustCompile(`definition\s+` + regexp.QuoteMeta(name) + `\s*\{`)
	return re.MatchString(liveSchema)
}

// Client wraps an authzed-go *Client with helpers and config.
type Client struct {
	c        *authzed.Client
	endpoint string
}

// NewClient connects to spicedb at endpoint (host:port). Uses TLS with
// InsecureSkipVerify (the in-cluster cert is signed by example-tenant
// CA which talon's cert chain doesn't yet load; Linkerd handles wire
// mTLS underneath). PSK is sent via gRPC bearer-token auth.
func NewClient(endpoint, psk string) (*Client, error) {
	if endpoint == "" {
		return nil, errors.New("spicedb endpoint is required")
	}
	if psk == "" {
		return nil, errors.New("spicedb PSK is required")
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // in-cluster cert; Linkerd mTLS overlays
		MinVersion:         tls.VersionTLS12,
	}
	c, err := authzed.NewClient(endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpcutil.WithBearerToken(psk),
	)
	if err != nil {
		return nil, fmt.Errorf("spicedb dial %s: %w", endpoint, err)
	}
	return &Client{c: c, endpoint: endpoint}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error { return c.c.Close() }

// EnsureSchema verifies that every definition Talon requires (per the
// embedded schemaZed) is present in the LIVE cluster SpiceDB schema.
// It does NOT call WriteSchema — see schemaZed's doc comment for why:
// WriteSchema is now exclusively owned by the dedicated
// `spicedb-schema` Argo CD Application. Talon only ever reads.
//
// Safe to call from every Talon pod at startup: ReadSchema is a pure
// read, so concurrent pods never race each other or the schema-owning
// Application. Callers should treat a verification failure as fatal
// at startup (Phase 2.1 contract: no verified SpiceDB schema = no
// Talon) — the same fail-closed posture the old write-based
// EnsureSchema had, now covering "schema exists but is missing what
// Talon needs" as well as "SpiceDB unreachable".
//
// Returns the ZedToken from the ReadSchema response's ReadAt on
// success (parity with the old WriteSchema-token log line).
func (c *Client) EnsureSchema(ctx context.Context) (string, error) {
	resp, err := c.c.ReadSchema(ctx, &v1pb.ReadSchemaRequest{})
	if err != nil {
		return "", fmt.Errorf("spicedb ReadSchema: %w", err)
	}
	live := resp.GetSchemaText()

	required := definitionNames(schemaZed)
	if len(required) == 0 {
		// Refuse to report a false pass — an empty embedded schema
		// almost certainly means schema.zed regressed to a stub/typo,
		// not that Talon genuinely requires zero definitions.
		return "", errors.New("spicedb EnsureSchema: BUG — embedded schema.zed has zero definitions, refusing to report a false pass")
	}

	var missing []string
	for _, name := range required {
		if !hasDefinition(live, name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("spicedb EnsureSchema: live schema is missing required definition(s) %v — either the spicedb-schema Application (hexxlock/falcon-id.git:deploy/helm/spicedb-schema) hasn't synced yet, or something wrote an incompatible schema; live schema as read back:\n%s", missing, live)
	}

	return resp.GetReadAt().GetToken(), nil
}

// HostObjectID encodes a DNS host into a SpiceDB ObjectId. SpiceDB's
// ObjectId regex forbids '.', so DNS hosts are encoded with '_'
// separator. Reversible (no '_' in legal DNS labels) and stable.
//
// Reference: https://authzed.com/docs/spicedb/concepts/objects (the
// regex is `^[a-zA-Z0-9/_|\\-=+]{1,}$|^\\*$`).
func HostObjectID(host string) string {
	return strings.ReplaceAll(host, ".", "_")
}

// CheckPermission is the per-request authz call. Returns true if the
// subject has the permission on the talon_route resource. Wraps with
// the configured deadline; returns (false, err) on transport / timeout
// failure (caller fail-closes per ADR 0001 §7.b).
func (c *Client) CheckPermission(ctx context.Context, req CheckRequest) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, req.Deadline)
	defer cancel()

	resp, err := c.c.CheckPermission(cctx, &v1pb.CheckPermissionRequest{
		Resource: &v1pb.ObjectReference{
			ObjectType: "talon_route",
			ObjectId:   HostObjectID(req.Host),
		},
		Permission: req.Permission,
		Subject: &v1pb.SubjectReference{
			Object: &v1pb.ObjectReference{ObjectType: "user", ObjectId: req.Subject},
		},
		Consistency: &v1pb.Consistency{
			Requirement: &v1pb.Consistency_MinimizeLatency{MinimizeLatency: true},
		},
	})
	if err != nil {
		return false, fmt.Errorf("spicedb CheckPermission: %w", err)
	}
	return resp.GetPermissionship() == v1pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// CheckRequest is the input shape for CheckPermission. Fields match
// SpiceDB's CheckPermissionRequest; Deadline defaults to 200ms per ADR
// 0001 §7.b if zero.
type CheckRequest struct {
	Host       string        // public host, e.g. internal.example.com
	Subject    string        // Falcon-ID `sub` claim (UUID)
	Permission string        // viewer | editor | admin | access (per schema)
	Deadline   time.Duration // 200ms typical; 0 = use 200ms default
	// Privileged selects the shorter DDIL offline-decision budget (5m vs
	// 15m) for privileged / step-up / high-sensitivity routes. Set by the
	// PE from the route's ZTNA sensitivity. Zero value (false) = standard.
	Privileged bool
}

// Default returns a CheckRequest with Deadline filled in if missing.
func (r CheckRequest) Default() CheckRequest {
	if r.Deadline == 0 {
		r.Deadline = 200 * time.Millisecond
	}
	if r.Permission == "" {
		r.Permission = "access"
	}
	return r
}

// WriteRouteRelationships writes the cluster-default relationships for
// a TalonRoute: per-route bindings for each allowed group/subject. The
// reconciler calls this on Reconcile (after RegisterUpstream) per ADR
// 0003 §5.1.
//
// Idempotent — SpiceDB's TOUCH operation is upsert-style.
func (c *Client) WriteRouteRelationships(ctx context.Context, host string, allowedGroups, allowedSubjects []string, permission string) error {
	if permission == "" {
		permission = "viewer"
	}
	updates := make([]*v1pb.RelationshipUpdate, 0, len(allowedGroups)+len(allowedSubjects))
	hostID := HostObjectID(host)

	for _, g := range allowedGroups {
		updates = append(updates, &v1pb.RelationshipUpdate{
			Operation: v1pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1pb.Relationship{
				Resource: &v1pb.ObjectReference{ObjectType: "talon_route", ObjectId: hostID},
				Relation: permission,
				Subject: &v1pb.SubjectReference{
					Object:           &v1pb.ObjectReference{ObjectType: "group", ObjectId: g},
					OptionalRelation: "member",
				},
			},
		})
	}
	for _, s := range allowedSubjects {
		updates = append(updates, &v1pb.RelationshipUpdate{
			Operation: v1pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1pb.Relationship{
				Resource: &v1pb.ObjectReference{ObjectType: "talon_route", ObjectId: hostID},
				Relation: permission,
				Subject:  &v1pb.SubjectReference{Object: &v1pb.ObjectReference{ObjectType: "user", ObjectId: s}},
			},
		})
	}
	if len(updates) == 0 {
		return nil
	}

	_, err := c.c.WriteRelationships(ctx, &v1pb.WriteRelationshipsRequest{Updates: updates})
	if err != nil {
		return fmt.Errorf("spicedb WriteRelationships: %w", err)
	}
	return nil
}

// WriteUserGroupMemberships TOUCHes `group:<role>#member@user:<sub>`
// for each role the user carries on a successful login. This is the
// missing bridge between Falcon-ID's OIDC `roles` claim and the
// SpiceDB graph used by per-route CheckPermission:
//
//   TalonRoute reconciler writes
//       talon_route#editor@group:platform_admin#member
//   Login flow (this function) writes
//       group:platform_admin#member@user:<sub>
//   Per-request CheckPermission then walks
//       user:<sub> → group:platform_admin#member → talon_route#editor
//
// Without this call the cluster is misseeded and every protected
// route returns reason=no_permission even though the user has the
// right role on their JWT — the exact 2026-05-08 production outage
// the operator hit on internal.example.com.
//
// Idempotent (TOUCH = upsert) and bounded in size (typical user has
// ≤8 roles), so safe to call from the per-login hot path. Callers
// should not block on errors — fail-open with a WARN log is the
// right shape because the route-level permission check is the
// authoritative gate; a transient SpiceDB failure here just means
// the user re-establishes the relation on the next login.
func (c *Client) WriteUserGroupMemberships(ctx context.Context, sub string, roles []string) error {
	if sub == "" || len(roles) == 0 {
		return nil
	}
	updates := make([]*v1pb.RelationshipUpdate, 0, len(roles))
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		updates = append(updates, &v1pb.RelationshipUpdate{
			Operation: v1pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &v1pb.Relationship{
				Resource: &v1pb.ObjectReference{ObjectType: "group", ObjectId: role},
				Relation: "member",
				Subject:  &v1pb.SubjectReference{Object: &v1pb.ObjectReference{ObjectType: "user", ObjectId: sub}},
			},
		})
	}
	if len(updates) == 0 {
		return nil
	}
	_, err := c.c.WriteRelationships(ctx, &v1pb.WriteRelationshipsRequest{Updates: updates})
	if err != nil {
		return fmt.Errorf("spicedb WriteRelationships (group memberships): %w", err)
	}
	return nil
}

// DeleteUserGroupMemberships removes ALL `group:*#member@user:<sub>`
// relations for the given subject. Called from the back-channel
// logout path so a user who's removed from a role in Falcon-ID loses
// SpiceDB access on the next session refresh, not on the next 7d
// SpiceDB cache TTL. The DELETE form here is keyed on the subject
// (cleaner than enumerating every role group); SpiceDB iterates
// matching relationships server-side.
func (c *Client) DeleteUserGroupMemberships(ctx context.Context, sub string) error {
	if sub == "" {
		return nil
	}
	_, err := c.c.DeleteRelationships(ctx, &v1pb.DeleteRelationshipsRequest{
		RelationshipFilter: &v1pb.RelationshipFilter{
			ResourceType:     "group",
			OptionalRelation: "member",
			OptionalSubjectFilter: &v1pb.SubjectFilter{
				SubjectType:       "user",
				OptionalSubjectId: sub,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("spicedb DeleteRelationships (group memberships for %s): %w", sub, err)
	}
	return nil
}

// DeleteRouteRelationships removes all relationships referencing the
// given route's resource id. Called by the reconciler on TalonRoute
// deletion.
func (c *Client) DeleteRouteRelationships(ctx context.Context, host string) error {
	_, err := c.c.DeleteRelationships(ctx, &v1pb.DeleteRelationshipsRequest{
		RelationshipFilter: &v1pb.RelationshipFilter{
			ResourceType:       "talon_route",
			OptionalResourceId: HostObjectID(host),
		},
	})
	if err != nil {
		return fmt.Errorf("spicedb DeleteRelationships: %w", err)
	}
	return nil
}
