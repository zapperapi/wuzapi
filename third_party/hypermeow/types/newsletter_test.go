package types

import (
	"encoding/json"
	"testing"
)

// Resposta no formato de WAWebMexFetchAllNewslettersMetadataJobQuery: sem
// "mute" em viewer_metadata, com o estado em settings.
func TestNewsletterMetadataDerivesMuteFromViewerSettings(t *testing.T) {
	raw := `{
		"id": "120363000000000001@newsletter",
		"state": {"type": "ACTIVE"},
		"thread_metadata": {
			"creation_time": "1700000000",
			"name": {"id": "1", "text": "Canal", "update_time": "1700000000000000"},
			"description": {"id": "2", "text": "Descrição", "update_time": "1700000000000000"},
			"invite": "0029VaAbCdEfGhIjKlMnOp",
			"handle": null,
			"verification": "UNVERIFIED",
			"picture": {"id": "10", "type": "IMAGE", "direct_path": "/v/t61/full.jpg"},
			"preview": {"id": "10", "type": "PREVIEW", "direct_path": "/v/t61/preview.jpg"},
			"settings": {"reaction_codes": {"value": "ALL"}}
		},
		"viewer_metadata": {
			"role": "OWNER",
			"settings": [
				{"type": "MUTE_FOLLOWER_ACTIVITY", "value": "OFF"},
				{"type": "MUTE_ADMIN_ACTIVITY", "value": "ON"}
			]
		}
	}`
	var meta NewsletterMetadata
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.ViewerMeta == nil {
		t.Fatal("viewer_metadata was not decoded")
	}
	if meta.ViewerMeta.Mute != NewsletterMuteOn {
		t.Errorf("mute = %q, want %q", meta.ViewerMeta.Mute, NewsletterMuteOn)
	}
	if meta.ViewerMeta.Role != NewsletterRoleOwner {
		t.Errorf("role = %q, want %q", meta.ViewerMeta.Role, NewsletterRoleOwner)
	}
	if len(meta.ViewerMeta.Settings) != 2 {
		t.Errorf("settings = %#v, want 2 items", meta.ViewerMeta.Settings)
	}
	if meta.ThreadMeta.Name.Text != "Canal" || meta.ThreadMeta.InviteCode != "0029VaAbCdEfGhIjKlMnOp" {
		t.Errorf("thread metadata = %#v", meta.ThreadMeta)
	}
	if meta.ThreadMeta.Picture == nil || meta.ThreadMeta.Preview.DirectPath != "/v/t61/preview.jpg" {
		t.Errorf("picture = %#v, preview = %#v", meta.ThreadMeta.Picture, meta.ThreadMeta.Preview)
	}
}

func TestNewsletterViewerMetadataMuteStates(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want NewsletterMuteState
	}{
		{"unmuted", `{"role":"SUBSCRIBER","settings":[{"type":"MUTE_ADMIN_ACTIVITY","value":"OFF"}]}`, NewsletterMuteOff},
		{"legacy mute field wins", `{"role":"SUBSCRIBER","mute":"ON","settings":[{"type":"MUTE_ADMIN_ACTIVITY","value":"OFF"}]}`, NewsletterMuteOn},
		{"follower activity is not the channel mute", `{"role":"ADMIN","settings":[{"type":"MUTE_FOLLOWER_ACTIVITY","value":"ON"}]}`, ""},
		{"no settings", `{"role":"GUEST"}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var meta NewsletterViewerMetadata
			if err := json.Unmarshal([]byte(tc.raw), &meta); err != nil {
				t.Fatal(err)
			}
			if meta.Mute != tc.want {
				t.Fatalf("mute = %q, want %q", meta.Mute, tc.want)
			}
		})
	}
}
