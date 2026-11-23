package main

import (
	"errors"
	"testing"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/polymorfa/hypermeow/types"
	"google.golang.org/protobuf/proto"
)

func TestWrapGroupStatusWrapsAndMarksRequest(t *testing.T) {
	group := types.NewJID("120363432973143805", types.GroupServer)
	inner := &waE2E.Message{Conversation: proto.String("oi")}
	extra := whatsmeow.SendRequestExtra{ID: "ID1"}

	wrapped, err := wrapGroupStatus(group, inner, &extra)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrapped.GetGroupStatusMessageV2().GetMessage() != inner {
		t.Fatal("payload is not wrapped in GroupStatusMessageV2")
	}
	if len(wrapped.GetMessageContextInfo().GetMessageSecret()) != 32 {
		t.Fatal("message secret must have 32 bytes")
	}
	if extra.Meta == nil || !extra.Meta.IsGroupStatus {
		t.Fatal("send request is not marked as group status")
	}
	if extra.ID != "ID1" {
		t.Fatal("send request ID changed")
	}
}

func TestWrapGroupStatusRejectsNonGroup(t *testing.T) {
	user := types.NewJID("5512991982175", types.DefaultUserServer)
	extra := whatsmeow.SendRequestExtra{}

	_, err := wrapGroupStatus(user, &waE2E.Message{}, &extra)
	if !errors.Is(err, errGroupStatusRequiresGroup) {
		t.Fatalf("expected errGroupStatusRequiresGroup, got %v", err)
	}
	if extra.Meta != nil {
		t.Fatal("send request must not be marked")
	}
}
