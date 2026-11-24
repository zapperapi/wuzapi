// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"go.mau.fi/util/jsontime"

	"github.com/polymorfa/hypermeow/proto/waE2E"
)

type NewsletterVerificationState string

func (nvs *NewsletterVerificationState) UnmarshalText(text []byte) error {
	*nvs = NewsletterVerificationState(bytes.ToLower(text))
	return nil
}

const (
	NewsletterVerificationStateVerified   NewsletterVerificationState = "verified"
	NewsletterVerificationStateUnverified NewsletterVerificationState = "unverified"
)

type NewsletterPrivacy string

func (np *NewsletterPrivacy) UnmarshalText(text []byte) error {
	*np = NewsletterPrivacy(bytes.ToLower(text))
	return nil
}

const (
	NewsletterPrivacyPrivate NewsletterPrivacy = "private"
	NewsletterPrivacyPublic  NewsletterPrivacy = "public"
)

type NewsletterReactionsMode string

const (
	NewsletterReactionsModeAll       NewsletterReactionsMode = "all"
	NewsletterReactionsModeBasic     NewsletterReactionsMode = "basic"
	NewsletterReactionsModeNone      NewsletterReactionsMode = "none"
	NewsletterReactionsModeBlocklist NewsletterReactionsMode = "blocklist"
)

type NewsletterState string

func (ns *NewsletterState) UnmarshalText(text []byte) error {
	*ns = NewsletterState(bytes.ToLower(text))
	return nil
}

const (
	NewsletterStateActive       NewsletterState = "active"
	NewsletterStateSuspended    NewsletterState = "suspended"
	NewsletterStateGeoSuspended NewsletterState = "geosuspended"
)

type NewsletterMuted struct {
	Muted bool
}

type WrappedNewsletterState struct {
	Type NewsletterState `json:"type"`
}

type NewsletterMuteState string

func (nms *NewsletterMuteState) UnmarshalText(text []byte) error {
	*nms = NewsletterMuteState(bytes.ToLower(text))
	return nil
}

const (
	NewsletterMuteOn  NewsletterMuteState = "on"
	NewsletterMuteOff NewsletterMuteState = "off"
)

type NewsletterRole string

func (nr *NewsletterRole) UnmarshalText(text []byte) error {
	*nr = NewsletterRole(bytes.ToLower(text))
	return nil
}

const (
	NewsletterRoleSubscriber NewsletterRole = "subscriber"
	NewsletterRoleGuest      NewsletterRole = "guest"
	NewsletterRoleAdmin      NewsletterRole = "admin"
	NewsletterRoleOwner      NewsletterRole = "owner"
)

type NewsletterMetadata struct {
	ID         JID                       `json:"id"`
	State      WrappedNewsletterState    `json:"state"`
	ThreadMeta NewsletterThreadMetadata  `json:"thread_metadata"`
	ViewerMeta *NewsletterViewerMetadata `json:"viewer_metadata"`
}

// Tipos e valores de XWA2NewsletterUserSetting (viewer_metadata.settings).
const (
	// NewsletterUserSettingMuteAdminActivity silencia as atualizações do canal.
	// É a configuração que o WhatsApp Web grava em muteExpiration do chat.
	NewsletterUserSettingMuteAdminActivity = "MUTE_ADMIN_ACTIVITY"
	// NewsletterUserSettingMuteFollowerActivity silencia, para o admin, os avisos
	// de atividade dos seguidores.
	NewsletterUserSettingMuteFollowerActivity = "MUTE_FOLLOWER_ACTIVITY"

	NewsletterUserSettingValueOn  = "ON"
	NewsletterUserSettingValueOff = "OFF"
)

type NewsletterUserSetting struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type NewsletterViewerMetadata struct {
	Mute     NewsletterMuteState     `json:"mute"`
	Role     NewsletterRole          `json:"role"`
	Settings []NewsletterUserSetting `json:"settings,omitempty"`
}

// UnmarshalJSON preenche Mute a partir de settings. As consultas atuais não
// devolvem mais o campo "mute": o estado vem em settings, no item
// MUTE_ADMIN_ACTIVITY.
func (nvm *NewsletterViewerMetadata) UnmarshalJSON(data []byte) error {
	type plain NewsletterViewerMetadata
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.Mute == "" {
		for _, setting := range decoded.Settings {
			if setting.Type == NewsletterUserSettingMuteAdminActivity {
				decoded.Mute = NewsletterMuteState(bytes.ToLower([]byte(setting.Value)))
				break
			}
		}
	}
	*nvm = NewsletterViewerMetadata(decoded)
	return nil
}

type NewsletterKeyType string

const (
	NewsletterKeyTypeJID    NewsletterKeyType = "JID"
	NewsletterKeyTypeInvite NewsletterKeyType = "INVITE"
)

type NewsletterReactionSettings struct {
	Value NewsletterReactionsMode `json:"value"`
}

type NewsletterSettings struct {
	ReactionCodes NewsletterReactionSettings `json:"reaction_codes"`
}

type NewsletterThreadMetadata struct {
	CreationTime      jsontime.UnixString         `json:"creation_time"`
	InviteCode        string                      `json:"invite"`
	Handle            string                      `json:"handle,omitempty"`
	Name              NewsletterText              `json:"name"`
	Description       NewsletterText              `json:"description"`
	SubscriberCount   int                         `json:"subscribers_count,string"`
	VerificationState NewsletterVerificationState `json:"verification"`
	Picture           *ProfilePictureInfo         `json:"picture"`
	Preview           ProfilePictureInfo          `json:"preview"`
	Settings          NewsletterSettings          `json:"settings"`

	//NewsletterMuted `json:"-"`
	//PrivacyType     NewsletterPrivacy       `json:"-"`
	//ReactionsMode   NewsletterReactionsMode `json:"-"`
	//State           NewsletterState         `json:"-"`
}

type NewsletterText struct {
	Text       string                   `json:"text"`
	ID         string                   `json:"id"`
	UpdateTime jsontime.UnixMicroString `json:"update_time"`
}

type NewsletterMessage struct {
	MessageServerID MessageServerID
	MessageID       MessageID
	Type            string
	Timestamp       time.Time
	ViewsCount      int
	ReactionCounts  map[string]int

	// This is only present when fetching messages, not in live updates
	Message *waE2E.Message
}

type GraphQLErrorExtensions struct {
	ErrorCode   int    `json:"error_code"`
	IsRetryable bool   `json:"is_retryable"`
	Severity    string `json:"severity"`
}

type GraphQLError struct {
	Extensions GraphQLErrorExtensions `json:"extensions"`
	Message    string                 `json:"message"`
	Path       []string               `json:"path"`
}

func (gqle GraphQLError) Error() string {
	return fmt.Sprintf("%d %s (%s)", gqle.Extensions.ErrorCode, gqle.Message, gqle.Extensions.Severity)
}

type GraphQLErrors []GraphQLError

func (gqles GraphQLErrors) Unwrap() []error {
	errs := make([]error, len(gqles))
	for i, gqle := range gqles {
		errs[i] = gqle
	}
	return errs
}

func (gqles GraphQLErrors) Error() string {
	if len(gqles) == 0 {
		return ""
	} else if len(gqles) == 1 {
		return gqles[0].Error()
	} else {
		return fmt.Sprintf("%v (and %d other errors)", gqles[0], len(gqles)-1)
	}
}

type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors GraphQLErrors   `json:"errors"`
}
