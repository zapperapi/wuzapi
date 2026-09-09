package meowcaller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/polymorfa/hypermeow"
	waBinary "github.com/polymorfa/hypermeow/binary"
	"github.com/polymorfa/hypermeow/store"
	waLog "github.com/polymorfa/hypermeow/util/log"
	"github.com/rs/zerolog"
)

// FORK PATCH tests (see UPSTREAM.md, patch 2). Upstream tested that the reflected
// nodeHandlers map still matched a pinned whatsmeow layout. hypermeow has no such
// map; what these cover instead is the public RawNodeHandler hook and the node
// policy the fork installs on it.

func newHookedEngine(t *testing.T) (*engine, *whatsmeow.Client) {
	t.Helper()
	wa := whatsmeow.NewClient(&store.Device{}, waLog.Noop)
	eng := newEngine(&Client{wa: wa, log: zerolog.Nop()})
	if err := eng.installRawNodeHandler(); err != nil {
		t.Fatalf("install raw call adapter: %v", err)
	}
	t.Cleanup(eng.stopRawNodeHandler)
	return eng, wa
}

func TestInstallRawNodeHandlerUsesPublicHook(t *testing.T) {
	_, wa := newHookedEngine(t)
	if wa.RawNodeHandler == nil {
		t.Fatal("raw call adapter did not install a RawNodeHandler")
	}
}

func TestInstallRawNodeHandlerRejectsMissingClient(t *testing.T) {
	eng := newEngine(&Client{log: zerolog.Nop()})
	if err := eng.installRawNodeHandler(); err == nil {
		t.Fatal("raw call adapter accepted a missing whatsmeow client")
	}
}

// A second installation would silently disable the first: RawNodeHandler is one
// field, not a list.
func TestInstallRawNodeHandlerRefusesToOverwrite(t *testing.T) {
	eng, _ := newHookedEngine(t)
	if err := eng.installRawNodeHandler(); err == nil {
		t.Fatal("raw call adapter overwrote an existing RawNodeHandler")
	}
}

// The node policy of research §R2, which is what keeps feature 018's events flowing.
func TestRawNodeHandlerNodePolicy(t *testing.T) {
	_, wa := newHookedEngine(t)

	for _, tc := range []struct {
		name     string
		node     waBinary.Node
		wantDrop bool
	}{
		{
			name:     "call ack is consumed",
			node:     waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"class": "call"}},
			wantDrop: true,
		},
		{
			// Dropping these would break receipts and message acks.
			name:     "non-call ack passes through",
			node:     waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"class": "receipt"}},
			wantDrop: false,
		},
		{
			// Never dropped: hypermeow's handleCallEvent must keep emitting the
			// events.Call* the platform already forwards to customers (SC-012).
			name:     "call stanza is observed, not consumed",
			node:     waBinary.Node{Tag: "call", Attrs: waBinary.Attrs{"from": "x@s.whatsapp.net"}},
			wantDrop: false,
		},
		{
			name:     "unrelated node is untouched",
			node:     waBinary.Node{Tag: "message"},
			wantDrop: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified, drop := wa.RawNodeHandler(context.Background(), &tc.node)
			if drop != tc.wantDrop {
				t.Fatalf("drop = %v, want %v", drop, tc.wantDrop)
			}
			if modified != nil {
				t.Fatalf("handler rewrote the node; it must never modify one")
			}
		})
	}
}

// The handler runs on the socket receive goroutine: a wedged engine must cost
// dropped call nodes, never a stalled connection.
func TestEnqueueRawNodeNeverBlocks(t *testing.T) {
	eng := newEngine(&Client{log: zerolog.Nop()})
	eng.rawNodes = make(chan *waBinary.Node, 1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < rawNodeQueueSize*4; i++ {
			eng.enqueueRawNode(&waBinary.Node{Tag: "call"})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("enqueueRawNode blocked the receive goroutine")
	}
}

// The engine must not share mutable state with hypermeow's own dispatch of the
// same <call> stanza.
func TestCloneNodeIsDeep(t *testing.T) {
	original := &waBinary.Node{
		Tag:   "call",
		Attrs: waBinary.Attrs{"from": "x@s.whatsapp.net"},
		Content: []waBinary.Node{{
			Tag:     "offer",
			Attrs:   waBinary.Attrs{"call-id": "abc"},
			Content: []byte{1, 2, 3},
		}},
	}

	clone := cloneNode(original)
	clone.Attrs["from"] = "tampered"
	kids := clone.Content.([]waBinary.Node)
	kids[0].Attrs["call-id"] = "tampered"
	kids[0].Content.([]byte)[0] = 9

	if got := original.Attrs["from"]; got != "x@s.whatsapp.net" {
		t.Fatalf("clone shares the attribute map: from = %v", got)
	}
	origKids := original.Content.([]waBinary.Node)
	if got := origKids[0].Attrs["call-id"]; got != "abc" {
		t.Fatalf("clone shares a child attribute map: call-id = %v", got)
	}
	if got := origKids[0].Content.([]byte)[0]; got != 1 {
		t.Fatalf("clone shares child content bytes: first byte = %d", got)
	}
}

func TestCloneNodeHandlesNil(t *testing.T) {
	if cloneNode(nil) != nil {
		t.Fatal("cloneNode(nil) must be nil")
	}
}

func TestGroupFeaturesRejectUnavailableRawAdapter(t *testing.T) {
	client := &Client{log: zerolog.Nop()}
	eng := newEngine(client)
	eng.rawCallHookErr = errors.New("upstream layout changed")
	if _, err := eng.placeGroupCall(
		context.Background(),
		[]string{"1", "2"},
		GroupCallOptions{},
	); err == nil {
		t.Fatal("group call continued without its raw call adapter")
	}
}
