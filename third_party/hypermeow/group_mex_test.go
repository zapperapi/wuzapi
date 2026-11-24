package whatsmeow

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/polymorfa/hypermeow/types"
)

func TestParseMexSubGroups(t *testing.T) {
	data := json.RawMessage(`{"xwa2_group_query_by_id":{
		"__typename":"XWA2CommunityGroup","id":"120363000000000001@g.us",
		"default_sub_group":{"id":"120363000000000002@g.us","subject":{"value":"Avisos","creation_time":"1795400000"}},
		"sub_groups":{"edges":[
			{"node":{"id":"120363000000000003@g.us","subject":{"value":"Geral","creation_time":1795400100},
				"properties":{"general_chat":true,"membership_approval_mode_enabled":false,"hidden_group":false},
				"membership_approval_requests":{"total_count":0}}},
			{"node":{"id":"120363000000000004","subject":{"value":"Fechado","creation_time":"1795400200"},
				"properties":{"general_chat":false,"membership_approval_mode_enabled":true,"hidden_group":true},
				"membership_approval_requests":{"total_count":1}}}
		]}}}`)

	groups, err := parseMexSubGroups(data)
	if err != nil {
		t.Fatalf("parseMexSubGroups: %v", err)
	}
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}

	announce := groups[0]
	if !announce.IsDefaultSubGroup || announce.Name != "Avisos" || announce.JID.String() != "120363000000000002@g.us" {
		t.Errorf("announcement group = %+v", announce)
	}
	if !announce.NameSetAt.Equal(time.Unix(1795400000, 0)) {
		t.Errorf("announcement NameSetAt = %v", announce.NameSetAt)
	}

	general := groups[1]
	if general.IsDefaultSubGroup || !general.IsGeneralChat || general.HasMembershipRequest {
		t.Errorf("general group = %+v", general)
	}
	if !general.NameSetAt.Equal(time.Unix(1795400100, 0)) {
		t.Errorf("general NameSetAt = %v", general.NameSetAt)
	}

	closed := groups[2]
	if closed.JID.String() != "120363000000000004@g.us" {
		t.Errorf("JID without server = %s", closed.JID)
	}
	if !closed.IsHidden || !closed.MembershipApprovalMode || !closed.HasMembershipRequest {
		t.Errorf("closed group = %+v", closed)
	}
}

func TestParseMexSubGroupsErrors(t *testing.T) {
	cases := []struct {
		name string
		data string
		want error
	}{
		{"not a community", `{"xwa2_group_query_by_id":{"__typename":"XWA2Group","id":"1@g.us"}}`, errMexGroupNotCommunity},
		{"no group", `{"xwa2_group_query_by_id":null}`, nil},
		{"no announcement", `{"xwa2_group_query_by_id":{"__typename":"XWA2CommunityGroup","sub_groups":{"edges":[]}}}`, nil},
		{"null node", `{"xwa2_group_query_by_id":{"__typename":"XWA2CommunityGroup","default_sub_group":{"id":"2@g.us"},"sub_groups":{"edges":[{"node":null}]}}}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseMexSubGroups(json.RawMessage(tc.data))
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMapMexGroupError(t *testing.T) {
	gql := func(code int) error {
		return fmt.Errorf("graphql error: %w", types.GraphQLErrors{{Extensions: types.GraphQLErrorExtensions{ErrorCode: code}}})
	}
	cases := []struct {
		name       string
		err        error
		unauth     error
		want       error
		definitive bool
	}{
		{"401 invite", gql(401), ErrGroupInviteLinkUnauthorized, ErrGroupInviteLinkUnauthorized, true},
		{"401 generic", gql(401), nil, ErrIQNotAuthorized, true},
		{"403", gql(403), nil, ErrNotInGroup, true},
		{"404", gql(404), nil, ErrGroupNotFound, true},
		{"400", gql(400), nil, nil, false},
		{"not graphql", errors.New("argo decoding is currently broken"), nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, definitive := mapMexGroupError(tc.err, tc.unauth)
			if definitive != tc.definitive {
				t.Errorf("definitive = %v, want %v", definitive, tc.definitive)
			}
			if tc.want != nil && !errors.Is(got, tc.want) {
				t.Errorf("err = %v, want %v", got, tc.want)
			}
			if tc.want == nil && got != tc.err {
				t.Errorf("err = %v, want the original error", got)
			}
		})
	}
}

func TestParseMexUnixTime(t *testing.T) {
	for raw, want := range map[string]int64{`"1795400000"`: 1795400000, `1795400000`: 1795400000, `null`: 0, `""`: 0, `"x"`: 0} {
		got := parseMexUnixTime(json.RawMessage(raw))
		if want == 0 {
			if !got.IsZero() {
				t.Errorf("%s: got %v, want zero", raw, got)
			}
			continue
		}
		if got.Unix() != want {
			t.Errorf("%s: got %d, want %d", raw, got.Unix(), want)
		}
	}
}
