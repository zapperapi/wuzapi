package main

import (
	"testing"

	"github.com/polymorfa/hypermeow/types"
)

// TestStatusJIDPrefersStore covers the case where userinfocache holds a stale
// empty Jid after pairing: /session/status must report the logged-in device.
func TestStatusJIDPrefersStore(t *testing.T) {
	storeID := types.NewADJID("5511999999999", 0, 12)

	if got, want := statusJID("", &storeID), storeID.String(); got != want {
		t.Errorf("stale empty cache: got %q, want %q", got, want)
	}
	if got, want := statusJID("5511888888888:3@s.whatsapp.net", &storeID), storeID.String(); got != want {
		t.Errorf("stale cache with old number: got %q, want %q", got, want)
	}
}

func TestStatusJIDFallsBackToCache(t *testing.T) {
	cached := "5511999999999:12@s.whatsapp.net"

	if got := statusJID(cached, nil); got != cached {
		t.Errorf("no store id: got %q, want %q", got, cached)
	}
	empty := types.EmptyJID
	if got := statusJID(cached, &empty); got != cached {
		t.Errorf("empty store id: got %q, want %q", got, cached)
	}
}
