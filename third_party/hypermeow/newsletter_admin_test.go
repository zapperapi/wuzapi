package whatsmeow

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/polymorfa/hypermeow/types"
)

var testNewsletter = types.NewJID("120363406995328786", types.NewsletterServer)

// IDs dos módulos WAWebMex*Newsletter* do WhatsApp Web 2.3000.1055901559.
func TestNewsletterAdminQueryIDsMatchWhatsAppWeb(t *testing.T) {
	got := map[string]string{
		"WAWebMexCreateNewsletterAdminInviteJobMutation": mutationCreateNewsletterAdminInvite,
		"WAWebMexAcceptNewsletterAdminInviteJobMutation": mutationAcceptNewsletterAdminInvite,
		"WAWebMexRevokeNewsletterAdminInviteJobMutation": mutationRevokeNewsletterAdminInvite,
		"WAWebMexDemoteNewsletterAdminJobMutation":       mutationDemoteNewsletterAdmin,
		"WAWebMexChangeNewsletterOwnerJobMutation":       mutationChangeNewsletterOwner,
		"WAWebMexFetchNewsletterPendingInvitesJobQuery":  queryNewsletterPendingAdminInvites,
		"WAWebMexFetchNewsletterAdminInfoJobQuery":       queryNewsletterAdminInfo,
		"WAWebMexNewsletterPinMessagesJobMutation":       mutationPinNewsletterMessages,
		"WAWebMexNewsletterUnpinMessagesJobMutation":     mutationUnpinNewsletterMessages,
		"WAWebMexFetchNewsletterInsightsJobQuery":        queryNewsletterInsights,
	}
	want := map[string]string{
		"WAWebMexCreateNewsletterAdminInviteJobMutation": "9387141988078609",
		"WAWebMexAcceptNewsletterAdminInviteJobMutation": "9580828702035549",
		"WAWebMexRevokeNewsletterAdminInviteJobMutation": "9656078347839416",
		"WAWebMexDemoteNewsletterAdminJobMutation":       "9880997548630971",
		"WAWebMexChangeNewsletterOwnerJobMutation":       "9546742745432473",
		"WAWebMexFetchNewsletterPendingInvitesJobQuery":  "28049623068067370",
		"WAWebMexFetchNewsletterAdminInfoJobQuery":       "26278439461859188",
		"WAWebMexNewsletterPinMessagesJobMutation":       "27165709459706559",
		"WAWebMexNewsletterUnpinMessagesJobMutation":     "28007176042216937",
		"WAWebMexFetchNewsletterInsightsJobQuery":        "9853618868050977",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("query IDs = %#v, want %#v", got, want)
	}
}

func TestBuildNewsletterUserVariablesRequiresLID(t *testing.T) {
	lid := types.NewJID("123456789012345", types.HiddenUserServer)
	got, err := buildNewsletterUserVariables(testNewsletter, lid)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"newsletter_id": "120363406995328786@newsletter",
		"user_id":       "123456789012345@lid",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("variables = %#v, want %#v", got, want)
	}

	device := types.JID{User: "123456789012345", Server: types.HiddenUserServer, Device: 3}
	got, err = buildNewsletterUserVariables(testNewsletter, device)
	if err != nil || got["user_id"] != "123456789012345@lid" {
		t.Fatalf("device JID: variables = %#v, err = %v", got, err)
	}

	pn := types.NewJID("5512991982175", types.DefaultUserServer)
	if _, err := buildNewsletterUserVariables(testNewsletter, pn); !errors.Is(err, ErrNewsletterUserNotLID) {
		t.Fatalf("phone number JID: error = %v, want %v", err, ErrNewsletterUserNotLID)
	}
}

func TestDecodeNewsletterAdminInviteExpiration(t *testing.T) {
	got, err := decodeNewsletterAdminInviteExpiration(json.RawMessage(`{"xwa2_newsletter_admin_invite_create":{"invite_expiration_time":"1796076362"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(time.Unix(1796076362, 0)) {
		t.Fatalf("expiration = %v", got)
	}
	if _, err := decodeNewsletterAdminInviteExpiration(json.RawMessage(`{"xwa2_newsletter_admin_invite_create":null}`)); err == nil {
		t.Fatal("expected an error without the expiration")
	}
}

func TestBuildNewsletterAdminInvite(t *testing.T) {
	msg := BuildNewsletterAdminInvite(NewsletterAdminInviteParams{
		Newsletter: testNewsletter,
		Name:       "Canal ZapperAPI",
		Caption:    "Seja admin",
		Expiration: time.Unix(1796076362, 0),
	})
	invite := msg.GetNewsletterAdminInviteMessage()
	if invite.GetNewsletterJID() != "120363406995328786@newsletter" || invite.GetNewsletterName() != "Canal ZapperAPI" ||
		invite.GetCaption() != "Seja admin" || invite.GetInviteExpiration() != 1796076362 || invite.JPEGThumbnail != nil {
		t.Fatalf("invite = %#v", invite)
	}
}

func TestDecodeNewsletterPendingAdminInvites(t *testing.T) {
	got, err := decodeNewsletterPendingAdminInvites(json.RawMessage(`{"xwa2_newsletter_admin":{"id":"120363406995328786@newsletter","pending_admin_invites":[{"user":{"id":"111@lid"}},{"user":null},{"user":{"id":"222@lid"}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].String() != "111@lid" || got[1].String() != "222@lid" {
		t.Fatalf("invited = %v", got)
	}
	empty, err := decodeNewsletterPendingAdminInvites(json.RawMessage(`{"xwa2_newsletter_admin":{"pending_admin_invites":null}}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty = %v, err = %v", empty, err)
	}
}

func TestDecodeNewsletterAdminCount(t *testing.T) {
	got, err := decodeNewsletterAdminCount(json.RawMessage(`{"xwa2_newsletter_admin":{"admin_count":3,"admin_settings":{"admin_profiles_enabled":false}}}`))
	if err != nil || got != 3 {
		t.Fatalf("count = %d, err = %v", got, err)
	}
	if _, err := decodeNewsletterAdminCount(json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected an error without xwa2_newsletter_admin")
	}
}

func TestDecodeNewsletterFollowers(t *testing.T) {
	raw := `{"xwa2_newsletter_followers":{"followers":{"edges":[
		{"node":{"id":"111@lid","display_name":"Ana","pn":"5512991982175@s.whatsapp.net","username_info":{"username":"ana"}},"role":"ADMIN","follow_time":"1760776422"},
		{"node":{"id":"222@lid","display_name":"","pn":null},"role":"SUBSCRIBER","follow_time":null},
		{"node":{"id":null}}
	]}}}`
	got, err := decodeNewsletterFollowers(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("followers = %d, want 2", len(got))
	}
	first := got[0]
	if first.ID.String() != "111@lid" || first.DisplayName != "Ana" || first.PhoneNumber.String() != "5512991982175@s.whatsapp.net" ||
		first.Username != "ana" || first.Role != types.NewsletterRoleAdmin || !first.FollowTime.Equal(time.Unix(1760776422, 0)) {
		t.Fatalf("first follower = %#v", first)
	}
	second := got[1]
	if !second.PhoneNumber.IsEmpty() || second.Role != types.NewsletterRoleSubscriber || !second.FollowTime.IsZero() {
		t.Fatalf("second follower = %#v", second)
	}

	empty, err := decodeNewsletterFollowers(json.RawMessage(`{"xwa2_newsletter_followers":{"followers":null}}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty = %v, err = %v", empty, err)
	}
}

func TestBuildNewsletterPinVariables(t *testing.T) {
	got, err := buildNewsletterPinVariables(testNewsletter, []types.MessageServerID{142, 143})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	want := `{"input":{"message_ids":["142","143"]},"newsletter_id":"120363406995328786@newsletter"}`
	if string(raw) != want {
		t.Fatalf("variables = %s, want %s", raw, want)
	}
	for _, ids := range [][]types.MessageServerID{nil, {0}, {142, -1}} {
		if _, err := buildNewsletterPinVariables(testNewsletter, ids); err == nil {
			t.Errorf("ids %v: expected an error", ids)
		}
	}
}

func TestDecodeNewsletterPinnedMessages(t *testing.T) {
	raw := `{"xwa2_newsletter_pin_messages":{"id":"120363406995328786@newsletter","thread_metadata":{"pinned_messages":[{"message_id":"142","expiry_ts":"1796076362"},{"message_id":"143","expiry_ts":null}]}}}`
	got, err := decodeNewsletterPinnedMessages(json.RawMessage(raw), "xwa2_newsletter_pin_messages")
	if err != nil {
		t.Fatal(err)
	}
	want := []types.NewsletterPinnedMessage{
		{ServerID: 142, Expiration: time.Unix(1796076362, 0)},
		{ServerID: 143},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned = %#v, want %#v", got, want)
	}
	if _, err := decodeNewsletterPinnedMessages(json.RawMessage(raw), "xwa2_newsletter_unpin_messages"); err == nil {
		t.Fatal("expected an error for the wrong response field")
	}
}

func TestNewsletterInsightMetricMatchesWhatsAppWebShape(t *testing.T) {
	raw, err := json.Marshal([]NewsletterInsightMetric{
		{ID: 6, Type: NewsletterInsightFollowers, GroupBy: NewsletterInsightGroupBy{NumberOfDays: 30}},
		{ID: 5, Type: NewsletterInsightUniqueVisitors, GroupBy: NewsletterInsightGroupBy{NumberOfDays: 30, Country: true}, Surface: "ALL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"id":6,"type":"FOLLOWER","group_by":{"number_of_days":30}},{"id":5,"type":"UNIQUE_VISITORS","group_by":{"number_of_days":30,"country":true},"surface":"ALL"}]`
	if string(raw) != want {
		t.Fatalf("metrics = %s, want %s", raw, want)
	}
}

func TestDecodeNewsletterInsights(t *testing.T) {
	raw := `{"xwa2_newsletter_admin_insights":{"newsletter_id":"120363406995328786@newsletter","last_update_time":"1796000000","metrics_status":"AVAILABLE","result":[
		{"id":6,"values":[{"value":"128","country":null,"role":null,"timestamp":null}]},
		{"id":7,"values":[{"value":100,"country":"BR"},{"value":28.5,"country":"PT"}]},
		{"id":4,"values":[{"value":"3","role":"SUBSCRIBER"}]}
	]}}`
	got, err := decodeNewsletterInsights(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "AVAILABLE" || !got.LastUpdate.Equal(time.Unix(1796000000, 0)) || len(got.Metrics) != 3 {
		t.Fatalf("insights = %#v", got)
	}
	if got.Metrics[0].ID != 6 || got.Metrics[0].Values[0].Value != 128 {
		t.Errorf("followers = %#v", got.Metrics[0])
	}
	if got.Metrics[1].Values[1].Country != "PT" || got.Metrics[1].Values[1].Value != 28.5 {
		t.Errorf("by country = %#v", got.Metrics[1])
	}
	if got.Metrics[2].Values[0].Role != "subscriber" {
		t.Errorf("by role = %#v", got.Metrics[2])
	}
	if _, err := decodeNewsletterInsights(json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected an error without xwa2_newsletter_admin_insights")
	}
}
