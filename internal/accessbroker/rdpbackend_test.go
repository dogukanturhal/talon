// SPDX-License-Identifier: AGPL-3.0-or-later

package accessbroker

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestJessRDPBackend_ProductionStubNotWired(t *testing.T) {
	be := NewJessRDPBackend(JessRDPBackendConfig{BrokerAddr: "jess-rdp.internal:9000"})
	_, err := be.DialRDP(context.Background(), RDPDialRequest{Target: "win-jump"})
	if !errors.Is(err, ErrRDPBackendNotWired) {
		t.Fatalf("production stub: err = %v, want ErrRDPBackendNotWired", err)
	}
}

func TestJessRDPBackend_SyntheticPaintsAndEchoesClipboard(t *testing.T) {
	be := NewJessRDPBackend(JessRDPBackendConfig{DevSynthetic: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := be.DialRDP(ctx, RDPDialRequest{Target: "win-jump", User: "admin", Width: 800, Height: 600})
	if err != nil {
		t.Fatalf("synthetic dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// First frame is the initial full-frame paint.
	first, err := conn.ReadFrame()
	if err != nil {
		t.Fatalf("read initial frame: %v", err)
	}
	if first.Kind != RDPMsgFrame || first.W != 800 || first.H != 600 {
		t.Fatalf("initial frame = %+v", first)
	}

	// A client clipboard paste is echoed back as a server clipboard offer
	// (so a round-trip test can observe the policy seam both ways).
	if err := conn.WriteInput(RDPClientMsg{Kind: RDPMsgClientClipboard, Data: []byte("hello")}); err != nil {
		t.Fatalf("write clipboard: %v", err)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("never observed echoed server clipboard")
		default:
		}
		msg, err := conn.ReadFrame()
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if msg.Kind == RDPMsgServerClipboard {
			if string(msg.Data) != "hello" {
				t.Fatalf("echoed clipboard = %q", msg.Data)
			}
			return
		}
	}
}

func TestNormalizeCanvasGeometry(t *testing.T) {
	if w, h := normalizeCanvasGeometry(0, 0); w != 1280 || h != 720 {
		t.Fatalf("zero geometry = %dx%d", w, h)
	}
	if w, h := normalizeCanvasGeometry(9000, 9000); w != 1280 || h != 720 {
		t.Fatalf("oversized geometry = %dx%d", w, h)
	}
	if w, h := normalizeCanvasGeometry(1024, 768); w != 1024 || h != 768 {
		t.Fatalf("valid geometry clamped to %dx%d", w, h)
	}
}
