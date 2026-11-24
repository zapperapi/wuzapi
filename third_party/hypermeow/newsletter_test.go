package whatsmeow

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/polymorfa/hypermeow/types"
)

// Os IDs vêm dos módulos WAWebMex*Newsletter*.graphql do WhatsApp Web
// 2.3000.1055901559. Um ID repetido já causou erro antes: os de seguir e de
// listar na variante desktop eram iguais.
func TestNewsletterQueryIDsMatchWhatsAppWeb(t *testing.T) {
	ids := map[string]string{
		"WAWebMexFetchNewsletterJobQuery":                queryFetchNewsletter,
		"WAWebMexFetchNewsletterDehydratedJobQuery":      queryFetchNewsletterDehydrated,
		"WAWebMexFetchRecommendedNewslettersJobQuery":    queryRecommendedNewsletters,
		"WAWebMexFetchNewsletterDirectoryListJobQuery":   queryNewslettersDirectory,
		"WAWebMexFetchAllNewslettersMetadataJobQuery":    querySubscribedNewsletters,
		"WAWebMexFetchNewsletterFollowersJobQuery":       queryNewsletterSubscribers,
		"WAWebMexUpdateNewsletterUserSettingJobMutation": mutationUpdateNewsletterUserSetting,
		"WAWebMexUpdateNewsletterJobMutation":            mutationUpdateNewsletter,
		"WAWebMexCreateNewsletterJobMutation":            mutationCreateNewsletter,
		"WAWebMexLeaveNewsletterJobMutation":             mutationUnfollowNewsletter,
		"WAWebMexJoinNewsletterJobMutation":              mutationFollowNewsletter,
		"WAWebMexDeleteNewsletterJobMutation":            mutationDeleteNewsletter,
	}
	want := map[string]string{
		"WAWebMexFetchNewsletterJobQuery":                "27456920720571478",
		"WAWebMexFetchNewsletterDehydratedJobQuery":      "26944199458535748",
		"WAWebMexFetchRecommendedNewslettersJobQuery":    "25806748772361516",
		"WAWebMexFetchNewsletterDirectoryListJobQuery":   "26125047313831973",
		"WAWebMexFetchAllNewslettersMetadataJobQuery":    "25399611239711790",
		"WAWebMexFetchNewsletterFollowersJobQuery":       "27472091235714801",
		"WAWebMexUpdateNewsletterUserSettingJobMutation": "31938993655691868",
		"WAWebMexUpdateNewsletterJobMutation":            "24250201037901610",
		"WAWebMexCreateNewsletterJobMutation":            "25149874324715067",
		"WAWebMexLeaveNewsletterJobMutation":             "9767147403369991",
		"WAWebMexJoinNewsletterJobMutation":              "24404358912487870",
		"WAWebMexDeleteNewsletterJobMutation":            "30062808666639665",
	}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("newsletter query IDs = %#v, want %#v", ids, want)
	}
	seen := make(map[string]string, len(ids))
	for name, id := range ids {
		if other, ok := seen[id]; ok {
			t.Errorf("%s and %s share the query ID %s", name, other, id)
		}
		seen[id] = name
	}
}

func TestBuildNewsletterInfoVariablesByJID(t *testing.T) {
	got := buildNewsletterInfoVariables(map[string]any{
		"key":  "120363000000000001@newsletter",
		"type": types.NewsletterKeyTypeJID,
	}, true)
	want := map[string]any{
		"fetch_creation_time":   true,
		"fetch_full_image":      true,
		"fetch_viewer_metadata": true,
		"fetch_wamo_sub":        false,
		"fetch_status_metadata": false,
		"fetch_pinned_messages": false,
		"input": map[string]any{
			"key":       "120363000000000001@newsletter",
			"type":      types.NewsletterKeyTypeJID,
			"view_role": "GUEST",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("variables = %#v, want %#v", got, want)
	}
}

func TestBuildNewsletterInfoVariablesByInviteSkipsFullImage(t *testing.T) {
	input := map[string]any{
		"key":  "0029VaAbCdEfGhIjKlMnOp",
		"type": types.NewsletterKeyTypeInvite,
	}
	got := buildNewsletterInfoVariables(input, false)
	if got["fetch_full_image"] != false {
		t.Errorf("fetch_full_image = %v, want false for an invite lookup", got["fetch_full_image"])
	}
	if got["fetch_viewer_metadata"] != false {
		t.Errorf("fetch_viewer_metadata = %v, want false", got["fetch_viewer_metadata"])
	}
	if _, ok := input["view_role"]; ok {
		t.Error("the caller's input map was modified")
	}
}

func TestBuildNewsletterInfoVariablesKeepsExplicitViewRole(t *testing.T) {
	got := buildNewsletterInfoVariables(map[string]any{
		"key":       "120363000000000001@newsletter",
		"type":      types.NewsletterKeyTypeJID,
		"view_role": "OWNER",
	}, true)
	if role := got["input"].(map[string]any)["view_role"]; role != "OWNER" {
		t.Fatalf("view_role = %v, want OWNER", role)
	}
}

func TestBuildNewsletterMuteVariables(t *testing.T) {
	jid := types.NewJID("120363000000000001", types.NewsletterServer)
	tests := map[bool]string{true: "ON", false: "OFF"}
	for mute, value := range tests {
		got, err := json.Marshal(buildNewsletterMuteVariables(jid, mute))
		if err != nil {
			t.Fatal(err)
		}
		want := `{"input":{"newsletter_id":"120363000000000001@newsletter","type":"MUTE_ADMIN_ACTIVITY","value":"` + value + `"}}`
		if string(got) != want {
			t.Errorf("mute=%t variables = %s, want %s", mute, got, want)
		}
	}
}

func TestCreateNewsletterParamsUseInputVariableShape(t *testing.T) {
	got, err := json.Marshal(map[string]any{"input": &CreateNewsletterParams{
		Name:        "Canal",
		Description: "Descrição",
		Picture:     []byte{0xff, 0xd8, 0xff},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"input":{"name":"Canal","description":"Descrição","picture":"/9j/"}}`
	if string(got) != want {
		t.Fatalf("variables = %s, want %s", got, want)
	}
}

func TestDecodeNewsletterMutationResponse(t *testing.T) {
	const field = "xwa2_newsletter_join_v2"
	tests := []struct {
		name string
		raw  string
		want error
	}{
		{"active", `{"xwa2_newsletter_join_v2":{"id":"1@newsletter","state":{"type":"ACTIVE"}}}`, nil},
		{"without state", `{"xwa2_newsletter_join_v2":{"id":"1@newsletter"}}`, nil},
		{"deleted", `{"xwa2_newsletter_join_v2":{"id":"1@newsletter","state":{"type":"DELETED"}}}`, ErrNewsletterNotFound},
		{"non existing", `{"xwa2_newsletter_join_v2":{"id":"1@newsletter","state":{"type":"NON_EXISTING"}}}`, ErrNewsletterNotFound},
		{"suspended", `{"xwa2_newsletter_join_v2":{"id":"1@newsletter","state":{"type":"SUSPENDED"}}}`, ErrNewsletterSuspended},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := decodeNewsletterMutationResponse(json.RawMessage(tc.raw), field)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecodeNewsletterMutationResponseRejectsMissingResult(t *testing.T) {
	tests := []string{
		`{"xwa2_newsletter_join_v2":null}`,
		`{"xwa2_newsletter_leave_v2":{"id":"1@newsletter","state":{"type":"ACTIVE"}}}`,
		`not json`,
	}
	for _, raw := range tests {
		if err := decodeNewsletterMutationResponse(json.RawMessage(raw), "xwa2_newsletter_join_v2"); err == nil {
			t.Errorf("expected an error for %s", raw)
		}
	}
}

func TestBuildUpdateNewsletterVariablesSendsOnlyEditedFields(t *testing.T) {
	jid := types.NewJID("120363000000000001", types.NewsletterServer)
	name := "Novo nome"
	got, err := buildUpdateNewsletterVariables(jid, UpdateNewsletterParams{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"newsletter_id":"120363000000000001@newsletter","updates":{"name":"Novo nome"}}`
	if string(raw) != want {
		t.Fatalf("variables = %s, want %s", raw, want)
	}
}

func TestBuildUpdateNewsletterVariablesEncodesPictureAndClearsWithEmptyValues(t *testing.T) {
	jid := types.NewJID("120363000000000001", types.NewsletterServer)
	description := ""
	picture := []byte{0xff, 0xd8, 0xff}
	got, err := buildUpdateNewsletterVariables(jid, UpdateNewsletterParams{Description: &description, Picture: &picture})
	if err != nil {
		t.Fatal(err)
	}
	updates := got["updates"].(map[string]any)
	if updates["description"] != "" {
		t.Errorf("description = %#v, want an empty string to remove it", updates["description"])
	}
	if updates["picture"] != "/9j/" {
		t.Errorf("picture = %#v, want base64 of the JPEG bytes", updates["picture"])
	}

	removed := []byte{}
	got, err = buildUpdateNewsletterVariables(jid, UpdateNewsletterParams{Picture: &removed})
	if err != nil {
		t.Fatal(err)
	}
	if picture := got["updates"].(map[string]any)["picture"]; picture != "" {
		t.Errorf("picture = %#v, want an empty string to remove it", picture)
	}
}

func TestBuildUpdateNewsletterVariablesRejectsEmptyUpdate(t *testing.T) {
	jid := types.NewJID("120363000000000001", types.NewsletterServer)
	if _, err := buildUpdateNewsletterVariables(jid, UpdateNewsletterParams{}); !errors.Is(err, ErrNoNewsletterUpdates) {
		t.Fatalf("error = %v, want %v", err, ErrNoNewsletterUpdates)
	}
}

// Formato observado no servidor em 2026-11-23, ao silenciar um canal.
func TestParseMexNotificationEventMapsUserSettingChangeToMuteChange(t *testing.T) {
	raw := `{"data":{"xwa2_notify_newsletter_on_user_setting_change":{"id":"120363406995328786@newsletter","setting":{"type":"MUTE_ADMIN_ACTIVITY","value":"ON"}}}}`
	evt, err := parseMexNotificationEvent([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if evt.MuteChange == nil {
		t.Fatal("mute change was not produced")
	}
	if evt.MuteChange.ID.String() != "120363406995328786@newsletter" || evt.MuteChange.Mute != types.NewsletterMuteOn {
		t.Fatalf("mute change = %#v", evt.MuteChange)
	}
}

func TestParseMexNotificationEventIgnoresOtherUserSettings(t *testing.T) {
	raw := `{"data":{"xwa2_notify_newsletter_on_user_setting_change":{"id":"120363406995328786@newsletter","setting":{"type":"MUTE_FOLLOWER_ACTIVITY","value":"ON"}}}}`
	evt, err := parseMexNotificationEvent([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if evt.MuteChange != nil {
		t.Fatalf("follower activity produced a mute change: %#v", evt.MuteChange)
	}
}

func TestParseMexNotificationEventKeepsJoinAndLeave(t *testing.T) {
	leave, err := parseMexNotificationEvent([]byte(`{"data":{"xwa2_notify_newsletter_on_leave":{"id":"120363144038483540@newsletter","role":"GUEST"}}}`))
	if err != nil || leave.Leave == nil || leave.Leave.Role != types.NewsletterRoleGuest {
		t.Fatalf("leave = %#v, err = %v", leave.Leave, err)
	}
	join, err := parseMexNotificationEvent([]byte(`{"data":{"xwa2_notify_newsletter_on_join":{"id":"120363144038483540@newsletter","state":{"type":"ACTIVE"}}}}`))
	if err != nil || join.Join == nil || join.Join.ID.String() != "120363144038483540@newsletter" {
		t.Fatalf("join = %#v, err = %v", join.Join, err)
	}
}
