package whatsmeow

import (
	"testing"

	waBinary "github.com/polymorfa/hypermeow/binary"
	"github.com/polymorfa/hypermeow/types"
)

func TestParseUSyncAbout(t *testing.T) {
	tests := []struct {
		name string
		user waBinary.Node
		want string
	}{
		{
			name: "legacy status",
			user: waBinary.Node{Tag: "user", Content: []waBinary.Node{
				{Tag: "status", Content: []byte("legacy about")},
			}},
			want: "legacy about",
		},
		{
			name: "text_status only",
			user: waBinary.Node{Tag: "user", Content: []waBinary.Node{
				{Tag: "text_status", Attrs: waBinary.Attrs{"text": "new about", "last_update_time": "1"}},
			}},
			want: "new about",
		},
		{
			name: "legacy status wins over text_status",
			user: waBinary.Node{Tag: "user", Content: []waBinary.Node{
				{Tag: "status", Content: []byte("legacy about")},
				{Tag: "text_status", Attrs: waBinary.Attrs{"text": "new about"}},
			}},
			want: "legacy about",
		},
		{
			name: "empty legacy status falls back to text_status",
			user: waBinary.Node{Tag: "user", Content: []waBinary.Node{
				{Tag: "status"},
				{Tag: "text_status", Attrs: waBinary.Attrs{"text": "new about"}},
			}},
			want: "new about",
		},
		{
			name: "text_status with error",
			user: waBinary.Node{Tag: "user", Content: []waBinary.Node{
				{Tag: "text_status", Content: []waBinary.Node{
					{Tag: "error", Attrs: waBinary.Attrs{"code": "401", "text": "not-authorized"}},
				}},
			}},
			want: "",
		},
		{
			name: "no about nodes",
			user: waBinary.Node{Tag: "user"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseUSyncAbout(&tt.user); got != tt.want {
				t.Fatalf("parseUSyncAbout() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseReceiptErrorType(t *testing.T) {
	integrityDrop := waBinary.Node{Tag: "receipt", Content: []waBinary.Node{
		{Tag: "error", Attrs: waBinary.Attrs{"type": "integrity-drop"}},
	}}
	if got := parseReceiptErrorType(&integrityDrop, types.ReceiptTypeError); got != "integrity-drop" {
		t.Fatalf("error receipt: got %q, want integrity-drop", got)
	}
	if got := parseReceiptErrorType(&integrityDrop, types.ReceiptTypeDelivered); got != "" {
		t.Fatalf("delivered receipt: got %q, want empty", got)
	}
	noChild := waBinary.Node{Tag: "receipt"}
	if got := parseReceiptErrorType(&noChild, types.ReceiptTypeError); got != "" {
		t.Fatalf("error receipt without <error>: got %q, want empty", got)
	}
}

func TestParseReceiptErrorReason(t *testing.T) {
	restricted := waBinary.Node{Tag: "receipt", Content: []waBinary.Node{
		{Tag: "biz", Attrs: waBinary.Attrs{"reason": "restricted_country_non_member"}},
		{Tag: "error", Attrs: waBinary.Attrs{"type": "feature-incapable"}},
	}}
	if got := parseReceiptErrorReason(&restricted, types.ReceiptTypeError); got != "restricted_country_non_member" {
		t.Fatalf("error receipt: got %q, want restricted_country_non_member", got)
	}
	if got := parseReceiptErrorType(&restricted, types.ReceiptTypeError); got != "feature-incapable" {
		t.Fatalf("error receipt type: got %q, want feature-incapable", got)
	}
	if got := parseReceiptErrorReason(&restricted, types.ReceiptTypeDelivered); got != "" {
		t.Fatalf("delivered receipt: got %q, want empty", got)
	}
	bizWithoutReason := waBinary.Node{Tag: "receipt", Content: []waBinary.Node{
		{Tag: "biz", Attrs: waBinary.Attrs{"host_storage": "2"}},
	}}
	if got := parseReceiptErrorReason(&bizWithoutReason, types.ReceiptTypeError); got != "" {
		t.Fatalf("error receipt with <biz> without reason: got %q, want empty", got)
	}
	noChild := waBinary.Node{Tag: "receipt"}
	if got := parseReceiptErrorReason(&noChild, types.ReceiptTypeError); got != "" {
		t.Fatalf("error receipt without <biz>: got %q, want empty", got)
	}
}
