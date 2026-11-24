package main

import (
	"reflect"
	"testing"

	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/polymorfa/hypermeow/types"
	"google.golang.org/protobuf/proto"
)

func TestMentionAllJIDsSkipsOwnAccount(t *testing.T) {
	ownPN := types.NewJID("5511888888888", types.DefaultUserServer)
	ownPN.Device = 12
	ownLID := types.NewJID("111111111111111", types.HiddenUserServer)

	info := &types.GroupInfo{Participants: []types.GroupParticipant{
		{JID: types.NewJID("5511999999999", types.DefaultUserServer)},
		// A própria conta num grupo em modo LID: o JID é o LID, o PN vem à parte.
		{
			JID:         types.NewJID("111111111111111", types.HiddenUserServer),
			PhoneNumber: types.NewJID("5511888888888", types.DefaultUserServer),
		},
		{JID: types.NewJID("222222222222222", types.HiddenUserServer)},
	}}

	got := mentionAllJIDs(info, ownPN, ownLID)
	want := []string{"5511999999999@s.whatsapp.net", "222222222222222@lid"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mentionAllJIDs = %v, want %v", got, want)
	}
}

func TestMentionAllJIDsNilGroup(t *testing.T) {
	if got := mentionAllJIDs(nil); got != nil {
		t.Fatalf("mentionAllJIDs(nil) = %v, want nil", got)
	}
}

func TestApplyExpiration(t *testing.T) {
	var ci *waE2E.ContextInfo
	applyExpiration(&ci, nil)
	if ci != nil {
		t.Fatal("sem Expiration, o ContextInfo não deve ser criado")
	}

	applyExpiration(&ci, proto.Uint32(0))
	if ci != nil {
		t.Fatal("Expiration zero não deve criar ContextInfo")
	}

	applyExpiration(&ci, proto.Uint32(604800))
	if ci.GetExpiration() != 604800 {
		t.Fatalf("Expiration = %d, want 604800", ci.GetExpiration())
	}

	existing := &waE2E.ContextInfo{StanzaID: proto.String("ABC")}
	applyExpiration(&existing, proto.Uint32(86400))
	if existing.GetStanzaID() != "ABC" || existing.GetExpiration() != 86400 {
		t.Fatalf("a citação existente deve ser mantida: %v", existing)
	}
}
