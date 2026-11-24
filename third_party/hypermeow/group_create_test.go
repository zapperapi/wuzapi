package whatsmeow

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/polymorfa/hypermeow/store"
	"github.com/polymorfa/hypermeow/types"
	waLog "github.com/polymorfa/hypermeow/util/log"
)

func newCreateGroupTestClient() *Client {
	ownID := types.NewJID("5511999990000", types.DefaultUserServer)
	device := &store.Device{
		ID:            &ownID,
		PrivacyTokens: &store.NoopStore{},
		LIDs:          &store.NoopStore{},
	}
	// Skip the background prune of expired tokens.
	return &Client{Store: device, Log: waLog.Noop, lastTCTokenDBPrune: time.Now()}
}

// The order and the defaults follow WAWebNewGroupFlow + WAWebGroupCreateJob +
// WASmaxGroupsCreateRPC (WhatsApp Web 2.3000.1055901559).
func TestBuildCreateGroupNodeMatchesWebNewGroupFlow(t *testing.T) {
	cli := newCreateGroupTestClient()
	participant := types.NewJID("5511988887777", types.DefaultUserServer)
	node, err := cli.buildCreateGroupNode(context.Background(), ReqCreateGroup{
		Name:         "Teste",
		Participants: []types.JID{participant},
	})
	if err != nil {
		t.Fatalf("buildCreateGroupNode: %v", err)
	}
	if node.Tag != "create" || node.AttrGetter().String("subject") != "Teste" {
		t.Fatalf("unexpected create node: %+v", node)
	}
	want := []string{"member_share_group_history_mode", "member_add_mode", "participant", "ephemeral", "membership_approval_mode"}
	if got := childTags(node); !slices.Equal(got, want) {
		t.Fatalf("child order = %v, want %v", got, want)
	}
	children := node.GetChildren()
	if got := children[0].Content; got != string(types.GroupMemberShareGroupHistoryModeAllMember) {
		t.Fatalf("member_share_group_history_mode = %v, want all_member_share", got)
	}
	if got := children[1].Content; got != string(types.GroupMemberAddModeAllMember) {
		t.Fatalf("member_add_mode = %v, want all_member_add", got)
	}
	if got := children[2].AttrGetter().JID("jid"); got != participant {
		t.Fatalf("participant jid = %v, want %v", got, participant)
	}
}

func TestBuildCreateGroupNodeKeepsExplicitShareMode(t *testing.T) {
	cli := newCreateGroupTestClient()
	node, err := cli.buildCreateGroupNode(context.Background(), ReqCreateGroup{
		Name:                        "Teste",
		MemberShareGroupHistoryMode: types.GroupMemberShareGroupHistoryModeAdmin,
	})
	if err != nil {
		t.Fatalf("buildCreateGroupNode: %v", err)
	}
	if got := node.GetChildren()[0].Content; got != string(types.GroupMemberShareGroupHistoryModeAdmin) {
		t.Fatalf("member_share_group_history_mode = %v, want admin_share", got)
	}
}

func TestBuildCreateGroupNodeOmitsShareModeForCommunity(t *testing.T) {
	cli := newCreateGroupTestClient()
	req := ReqCreateGroup{Name: "Comunidade"}
	req.IsParent = true
	node, err := cli.buildCreateGroupNode(context.Background(), req)
	if err != nil {
		t.Fatalf("buildCreateGroupNode: %v", err)
	}
	tags := childTags(node)
	if slices.Contains(tags, "member_share_group_history_mode") {
		t.Fatalf("community create must not carry member_share_group_history_mode: %v", tags)
	}
	if !slices.Contains(tags, "parent") {
		t.Fatalf("community create lost the parent node: %v", tags)
	}
}

func TestBuildCreateGroupNodePutsLinkedParentLast(t *testing.T) {
	cli := newCreateGroupTestClient()
	req := ReqCreateGroup{Name: "Subgrupo"}
	req.LinkedParentJID = types.NewJID("120363000000000000", types.GroupServer)
	node, err := cli.buildCreateGroupNode(context.Background(), req)
	if err != nil {
		t.Fatalf("buildCreateGroupNode: %v", err)
	}
	tags := childTags(node)
	if tags[len(tags)-1] != "linked_parent" {
		t.Fatalf("linked_parent should be the last child: %v", tags)
	}
}
