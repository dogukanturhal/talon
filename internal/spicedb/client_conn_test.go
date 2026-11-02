// SPDX-License-Identifier: AGPL-3.0-or-later

package spicedb

import (
	"context"
	"net"
	"testing"
	"time"

	v1pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type fakePerms struct {
	v1pb.UnimplementedPermissionsServiceServer
}

func (fakePerms) CheckPermission(context.Context, *v1pb.CheckPermissionRequest) (*v1pb.CheckPermissionResponse, error) {
	return &v1pb.CheckPermissionResponse{Permissionship: v1pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION}, nil
}

// delayListener delays Accept so a fresh connection takes a while to
// become READY, simulating DNS+TLS+mesh reconnect after idle.
type delayListener struct {
	net.Listener
	delay time.Duration
}

func (l delayListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		time.Sleep(l.delay)
	}
	return c, err
}

// A first check against a not-yet-READY conn must wait for the
// connection (up to connWait) before the 200ms RPC deadline starts.
func TestCheckPermission_ColdConnWaitsForReady(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	v1pb.RegisterPermissionsServiceServer(srv, fakePerms{})
	go srv.Serve(delayListener{lis, 600 * time.Millisecond})
	defer srv.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithIdleTimeout(0))
	if err != nil {
		t.Fatal(err)
	}
	c := newClientFromConn(conn, lis.Addr().String())
	defer c.Close()

	ok, err := c.CheckPermission(context.Background(), CheckRequest{
		Host: "a.example.com", Subject: "u1", Deadline: 200 * time.Millisecond, Permission: "access",
	})
	if err != nil || !ok {
		t.Fatalf("cold check = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestGroupObjectID(t *testing.T) {
	cases := map[string]string{
		"platform_admin":     "platform_admin", // already valid: identity
		"ops-team/a=b+c|d":   "ops-team/a=b+c|d",
		"accounting:manager": "accounting|3amanager",
		"a b":                "a|20b",
	}
	for in, want := range cases {
		if got := GroupObjectID(in); got != want {
			t.Errorf("GroupObjectID(%q) = %q, want %q", in, got, want)
		}
	}
}
