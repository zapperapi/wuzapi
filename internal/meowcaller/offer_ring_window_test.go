package meowcaller

import (
	"testing"
	"time"

	waBinary "github.com/polymorfa/hypermeow/binary"
)

func ringOffer(attrs waBinary.Attrs, children ...waBinary.Node) *waBinary.Node {
	if attrs == nil {
		attrs = waBinary.Attrs{}
	}
	attrs["call-id"] = "CALL1"
	return &waBinary.Node{Tag: "offer", Attrs: attrs, Content: children}
}

func silence(reason string) waBinary.Node {
	return waBinary.Node{Tag: "silence", Attrs: waBinary.Attrs{"reason": reason}}
}

func TestOfferSkipReason(t *testing.T) {
	cases := []struct {
		name   string
		offer  *waBinary.Node
		queued time.Duration
		want   string
	}{
		{"fresh offer rings", ringOffer(nil), 0, ""},
		{"just inside the window rings", ringOffer(nil), 89 * time.Second, ""},
		{"queued for the whole window does not ring", ringOffer(nil), 90 * time.Second, "expired"},
		{"queued for minutes does not ring", ringOffer(nil), 10 * time.Minute, "expired"},
		{"silenced by privacy does not ring", ringOffer(nil, silence("privacy")), 0, "silenced:privacy"},
		{"silenced as scheduled does not ring", ringOffer(nil, silence("scheduled")), 0, "silenced:scheduled"},
		{"unknown silence reason still rings", ringOffer(nil, silence("something_new")), 0, ""},
		{"silence without reason still rings", ringOffer(nil, waBinary.Node{Tag: "silence"}), 0, ""},
		{"silence wins over a fresh queue time", ringOffer(nil, silence("wave")), time.Second, "silenced:wave"},
		{"nil offer rings (nothing to judge)", nil, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := offerSkipReason(tc.offer, tc.queued); got != tc.want {
				t.Fatalf("offerSkipReason = %q, want %q", got, tc.want)
			}
		})
	}
}
