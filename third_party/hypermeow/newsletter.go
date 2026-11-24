// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	waBinary "github.com/polymorfa/hypermeow/binary"
	"github.com/polymorfa/hypermeow/proto/waWa6"
	"github.com/polymorfa/hypermeow/store"
	"github.com/polymorfa/hypermeow/types"
)

// NewsletterSubscribeLiveUpdates subscribes to receive live updates from a WhatsApp channel temporarily (for the duration returned).
func (cli *Client) NewsletterSubscribeLiveUpdates(ctx context.Context, jid types.JID) (time.Duration, error) {
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "newsletter",
		Type:      iqSet,
		To:        jid,
		Content: []waBinary.Node{{
			Tag: "live_updates",
		}},
	})
	if err != nil {
		return 0, err
	}
	child := resp.GetChildByTag("live_updates")
	dur := child.AttrGetter().Int("duration")
	return time.Duration(dur) * time.Second, nil
}

// NewsletterMarkViewed marks a channel message as viewed, incrementing the view counter.
//
// This is not the same as marking the channel as read on your other devices, use the usual MarkRead function for that.
func (cli *Client) NewsletterMarkViewed(ctx context.Context, jid types.JID, serverIDs []types.MessageServerID) error {
	if cli == nil {
		return ErrClientIsNil
	}
	items := make([]waBinary.Node, len(serverIDs))
	for i, id := range serverIDs {
		items[i] = waBinary.Node{
			Tag: "item",
			Attrs: waBinary.Attrs{
				"server_id": id,
			},
		}
	}
	reqID := cli.generateRequestID()
	resp := cli.waitResponse(reqID)
	err := cli.sendNode(ctx, waBinary.Node{
		Tag: "receipt",
		Attrs: waBinary.Attrs{
			"to":   jid,
			"type": "view",
			"id":   reqID,
		},
		Content: []waBinary.Node{{
			Tag:     "list",
			Content: items,
		}},
	})
	if err != nil {
		cli.cancelResponse(reqID, resp)
		return err
	}
	// TODO handle response?
	<-resp
	return nil
}

// NewsletterSendReaction sends a reaction to a channel message.
// To remove a reaction sent earlier, set reaction to an empty string.
//
// The last parameter is the message ID of the reaction itself. It can be left empty to let whatsmeow generate a random one.
func (cli *Client) NewsletterSendReaction(ctx context.Context, jid types.JID, serverID types.MessageServerID, reaction string, messageID types.MessageID) error {
	if messageID == "" {
		messageID = cli.GenerateMessageID()
	}
	reactionAttrs := waBinary.Attrs{}
	messageAttrs := waBinary.Attrs{
		"to":        jid,
		"id":        messageID,
		"server_id": serverID,
		"type":      "reaction",
	}
	if reaction != "" {
		reactionAttrs["code"] = reaction
	} else {
		messageAttrs["edit"] = string(types.EditAttributeSenderRevoke)
	}
	return cli.sendNode(ctx, waBinary.Node{
		Tag:   "message",
		Attrs: messageAttrs,
		Content: []waBinary.Node{{
			Tag:   "reaction",
			Attrs: reactionAttrs,
		}},
	})
}

// IDs das consultas MEX de canal do WhatsApp Web. Conferidos nos bundles
// 2.3000.1053682356 e 2.3000.1055901559 (módulos WAWebMex*Newsletter*.graphql).
// Ver WUZAPI_PATCHES.md, "IDs e formatos MEX de canal".
const (
	queryFetchNewsletter                = "27456920720571478" // WAWebMexFetchNewsletterJobQuery, output: xwa2_newsletter
	queryFetchNewsletterDehydrated      = "26944199458535748" // WAWebMexFetchNewsletterDehydratedJobQuery
	queryRecommendedNewsletters         = "25806748772361516" // WAWebMexFetchRecommendedNewslettersJobQuery, output: xwa2_newsletters_recommended
	queryNewslettersDirectory           = "26125047313831973" // WAWebMexFetchNewsletterDirectoryListJobQuery, output: xwa2_newsletters_directory_list
	querySubscribedNewsletters          = "25399611239711790" // WAWebMexFetchAllNewslettersMetadataJobQuery, variables -> {fetch_wamo_sub, fetch_status_metadata}, output: xwa2_newsletter_subscribed
	queryNewsletterSubscribers          = "27472091235714801" // WAWebMexFetchNewsletterFollowersJobQuery, output: xwa2_newsletter_followers
	mutationUpdateNewsletterUserSetting = "31938993655691868" // WAWebMexUpdateNewsletterUserSettingJobMutation, variables -> input -> {newsletter_id, type, value}, output: xwa2_newsletter_update_user_setting
	mutationUpdateNewsletter            = "24250201037901610" // WAWebMexUpdateNewsletterJobMutation, variables -> {newsletter_id, updates -> {name, description, picture, settings}}, output: xwa2_newsletter_update
	mutationCreateNewsletter            = "25149874324715067" // WAWebMexCreateNewsletterJobMutation, variables -> input -> {name, description, picture}, output: xwa2_newsletter_create
	mutationUnfollowNewsletter          = "9767147403369991"  // WAWebMexLeaveNewsletterJobMutation, output: xwa2_newsletter_leave_v2
	mutationFollowNewsletter            = "24404358912487870" // WAWebMexJoinNewsletterJobMutation, output: xwa2_newsletter_join_v2
	mutationDeleteNewsletter            = "30062808666639665"

	// desktop & mobile
	queryFetchNewsletterDesktop        = "9779843322044422"
	queryRecommendedNewslettersDesktop = "27256776790637714"
	querySubscribedNewslettersDesktop  = "8621797084555037"
	queryNewsletterSubscribersDesktop  = "25403502652570342"
	mutationMuteNewsletterDesktop      = "5971669009605755" // variables -> {newsletter_id, updates->{description, settings}}, output: xwa2_newsletter_update -> NewsletterMetadata without viewer meta
	mutationUnmuteNewsletterDesktop    = "6104029483058502"
	mutationUpdateNewsletterDesktop    = "7839742399440946"
	mutationCreateNewsletterDesktop    = "27527996220149684"
	mutationUnfollowNewsletterDesktop  = "8782612271820087"
	mutationFollowNewsletterDesktop    = "8621797084555037"
)

func convertQueryID(cli *Client, queryID string) string {
	if payload := cli.Store.GetClientPayload(); payload.GetUserAgent().Platform == waWa6.ClientPayload_UserAgent_MACOS.Enum() || payload.GetWebInfo() == nil {
		switch queryID {
		case queryFetchNewsletter:
			return queryFetchNewsletterDesktop
		case queryRecommendedNewsletters:
			return queryRecommendedNewslettersDesktop
		case querySubscribedNewsletters:
			return querySubscribedNewslettersDesktop
		case queryNewsletterSubscribers:
			return queryNewsletterSubscribersDesktop
		case mutationUpdateNewsletterUserSetting:
			// Silenciar pelo ID de desktop usava duas mutations antigas, com
			// outro formato de variáveis. Não há equivalente conferido.
			return ""
		case mutationUpdateNewsletter:
			return mutationUpdateNewsletterDesktop
		case mutationCreateNewsletter:
			return mutationCreateNewsletterDesktop
		case mutationUnfollowNewsletter:
			return mutationUnfollowNewsletterDesktop
		case mutationFollowNewsletter:
			return mutationFollowNewsletterDesktop
		case mutationDeleteNewsletter:
			return ""
		default:
			return queryID
		}
	} else {
		return queryID
	}
}

func (cli *Client) sendMexIQ(ctx context.Context, queryID string, variables any) (json.RawMessage, error) {
	if store.BaseClientPayload.GetUserAgent().GetPlatform() == waWa6.ClientPayload_UserAgent_MACOS {
		return nil, fmt.Errorf("argo decoding is currently broken")
	}
	queryID = convertQueryID(cli, queryID)
	if queryID == "" {
		return nil, fmt.Errorf("MEX query is unsupported for this client platform")
	}
	payload, err := json.Marshal(map[string]any{
		"variables": variables,
	})
	if err != nil {
		return nil, err
	}
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "w:mex",
		Type:      iqGet,
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag: "query",
			Attrs: waBinary.Attrs{
				"query_id": queryID,
			},
			Content: payload,
		}},
	})
	if err != nil {
		return nil, err
	}
	result, ok := resp.GetOptionalChildByTag("result")
	if !ok {
		return nil, &ElementMissingError{Tag: "result", In: "mex response"}
	}
	resultContent, ok := result.Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("unexpected content type %T in mex response", result.Content)
	}
	if result.AttrGetter().OptionalString("format") == "argo" {
		return nil, fmt.Errorf("argo decoding is currently broken")
	} else {
		var gqlResp types.GraphQLResponse
		err = json.Unmarshal(resultContent, &gqlResp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal graphql response: %w", err)
		} else if len(gqlResp.Errors) > 0 {
			return gqlResp.Data, fmt.Errorf("graphql error: %w", gqlResp.Errors)
		}
		return gqlResp.Data, nil
	}
}

type respGetNewsletterInfo struct {
	Newsletter *types.NewsletterMetadata `json:"xwa2_newsletter"`
}

// buildNewsletterInfoVariables monta as variáveis de WAWebMexFetchNewsletterJobQuery
// como o WhatsApp Web (WAWebMexFetchNewsletterJob): a imagem completa só é pedida
// na consulta por JID, e o papel de quem consulta vai em input.view_role.
func buildNewsletterInfoVariables(input map[string]any, fetchViewerMeta bool) map[string]any {
	queryInput := make(map[string]any, len(input)+1)
	for key, value := range input {
		queryInput[key] = value
	}
	if _, ok := queryInput["view_role"]; !ok {
		queryInput["view_role"] = newsletterViewRoleGuest
	}
	return map[string]any{
		"fetch_creation_time":   true,
		"fetch_full_image":      queryInput["type"] != types.NewsletterKeyTypeInvite,
		"fetch_viewer_metadata": fetchViewerMeta,
		"fetch_wamo_sub":        false,
		"fetch_status_metadata": false,
		"fetch_pinned_messages": false,
		"input":                 queryInput,
	}
}

func (cli *Client) getNewsletterInfo(ctx context.Context, input map[string]any, fetchViewerMeta bool) (*types.NewsletterMetadata, error) {
	data, err := cli.sendMexIQ(ctx, queryFetchNewsletter, buildNewsletterInfoVariables(input, fetchViewerMeta))
	var respData respGetNewsletterInfo
	if data != nil {
		jsonErr := json.Unmarshal(data, &respData)
		if err == nil && jsonErr != nil {
			err = jsonErr
		}
	}
	return respData.Newsletter, err
}

// GetNewsletterInfo gets the info of a newsletter that you're joined to.
func (cli *Client) GetNewsletterInfo(ctx context.Context, jid types.JID) (*types.NewsletterMetadata, error) {
	return cli.getNewsletterInfo(ctx, map[string]any{
		"key":  jid.String(),
		"type": types.NewsletterKeyTypeJID,
	}, true)
}

// GetNewsletterInfoWithInvite gets the info of a newsletter with an invite link.
//
// You can either pass the full link (https://whatsapp.com/channel/...) or just the `...` part.
//
// Note that the ViewerMeta field of the returned NewsletterMetadata will be nil.
func (cli *Client) GetNewsletterInfoWithInvite(ctx context.Context, key string) (*types.NewsletterMetadata, error) {
	return cli.getNewsletterInfo(ctx, map[string]any{
		"key":  stripURLPrefix(key, NewsletterLinkPrefix),
		"type": types.NewsletterKeyTypeInvite,
	}, false)
}

type respGetSubscribedNewsletters struct {
	Newsletters []*types.NewsletterMetadata `json:"xwa2_newsletter_subscribed"`
}

// GetSubscribedNewsletters gets the info of all newsletters that you're joined to.
func (cli *Client) GetSubscribedNewsletters(ctx context.Context) ([]*types.NewsletterMetadata, error) {
	data, err := cli.sendMexIQ(ctx, querySubscribedNewsletters, map[string]any{
		"fetch_wamo_sub":        false,
		"fetch_status_metadata": false,
	})
	var respData respGetSubscribedNewsletters
	if data != nil {
		jsonErr := json.Unmarshal(data, &respData)
		if err == nil && jsonErr != nil {
			err = jsonErr
		}
	}
	return respData.Newsletters, err
}

type CreateNewsletterParams struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Picture     []byte `json:"picture,omitempty"`
}

type respCreateNewsletter struct {
	Newsletter *types.NewsletterMetadata `json:"xwa2_newsletter_create"`
}

// CreateNewsletter creates a new WhatsApp channel.
func (cli *Client) CreateNewsletter(ctx context.Context, params CreateNewsletterParams) (*types.NewsletterMetadata, error) {
	// A variável do documento se chama "input"; "newsletter_input" é o nome do
	// argumento dentro da mutation (WAWebMexCreateNewsletterJob).
	resp, err := cli.sendMexIQ(ctx, mutationCreateNewsletter, map[string]any{
		"input": &params,
	})
	if err != nil {
		return nil, err
	}
	var respData respCreateNewsletter
	err = json.Unmarshal(resp, &respData)
	if err != nil {
		return nil, err
	}
	return respData.Newsletter, nil
}

// UpdateNewsletterParams lists the channel fields to change. A nil field is
// left as it is.
type UpdateNewsletterParams struct {
	// Name is the new channel name.
	Name *string
	// Description is the new description. An empty string removes it.
	Description *string
	// Picture is the new JPEG picture. An empty slice removes the picture.
	Picture *[]byte
}

// ErrNoNewsletterUpdates is returned when UpdateNewsletter is called without any field to change.
var ErrNoNewsletterUpdates = errors.New("no newsletter fields to update")

// buildUpdateNewsletterVariables monta as variáveis de WAWebMexUpdateNewsletterJobMutation
// como o WhatsApp Web (WAWebNewsletterMetadataQueryJob): só os campos editados
// entram em "updates"; a foto vai em base64, e uma string vazia apaga o campo.
func buildUpdateNewsletterVariables(jid types.JID, params UpdateNewsletterParams) (map[string]any, error) {
	updates := map[string]any{}
	if params.Name != nil {
		updates["name"] = *params.Name
	}
	if params.Description != nil {
		updates["description"] = *params.Description
	}
	if params.Picture != nil {
		updates["picture"] = base64.StdEncoding.EncodeToString(*params.Picture)
	}
	if len(updates) == 0 {
		return nil, ErrNoNewsletterUpdates
	}
	return map[string]any{
		"newsletter_id": jid.String(),
		"updates":       updates,
	}, nil
}

type respUpdateNewsletter struct {
	Newsletter *types.NewsletterMetadata `json:"xwa2_newsletter_update"`
}

// UpdateNewsletter changes the name, the description or the picture of a
// WhatsApp channel the client owns or administers.
//
// The returned metadata has no ViewerMeta.
func (cli *Client) UpdateNewsletter(ctx context.Context, jid types.JID, params UpdateNewsletterParams) (*types.NewsletterMetadata, error) {
	variables, err := buildUpdateNewsletterVariables(jid, params)
	if err != nil {
		return nil, err
	}
	resp, err := cli.sendMexIQ(ctx, mutationUpdateNewsletter, variables)
	if err != nil {
		return nil, err
	}
	var respData respUpdateNewsletter
	if err = json.Unmarshal(resp, &respData); err != nil {
		return nil, err
	}
	if respData.Newsletter == nil {
		return nil, fmt.Errorf("newsletter response is missing xwa2_newsletter_update")
	}
	return respData.Newsletter, nil
}

// AcceptTOSNotice accepts a ToS notice.
//
// To accept the terms for creating newsletters, use
//
//	cli.AcceptTOSNotice("20601218", "5")
func (cli *Client) AcceptTOSNotice(ctx context.Context, noticeID, stage string) error {
	_, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "tos",
		Type:      iqSet,
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag: "notice",
			Attrs: waBinary.Attrs{
				"id":    noticeID,
				"stage": stage,
			},
		}},
	})
	return err
}

// Papel informado em input.view_role na consulta de canal. O WhatsApp Web manda
// GUEST quando não conhece o papel local (WAWebNewsletterHandleMexGetNewsletter).
const newsletterViewRoleGuest = "GUEST"

var (
	// ErrNewsletterNotFound is returned when the channel was deleted or does not exist.
	ErrNewsletterNotFound = errors.New("newsletter was deleted or does not exist")
	// ErrNewsletterSuspended is returned when the channel is suspended.
	ErrNewsletterSuspended = errors.New("newsletter is suspended")
)

func buildNewsletterMuteVariables(jid types.JID, mute bool) map[string]any {
	value := types.NewsletterUserSettingValueOff
	if mute {
		value = types.NewsletterUserSettingValueOn
	}
	return map[string]any{
		"input": map[string]any{
			"newsletter_id": jid.String(),
			"type":          types.NewsletterUserSettingMuteAdminActivity,
			"value":         value,
		},
	}
}

// decodeNewsletterMutationResponse valida a resposta XWA2NewsletterMutationResponse
// das mutations de seguir, sair e silenciar, como WAWebMexJoinNewsletterJob.
func decodeNewsletterMutationResponse(data json.RawMessage, field string) error {
	var response map[string]*struct {
		ID    string `json:"id"`
		State *struct {
			Type string `json:"type"`
		} `json:"state"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("decode %s response: %w", field, err)
	}
	result := response[field]
	if result == nil {
		return fmt.Errorf("newsletter response is missing %s", field)
	}
	if result.State == nil {
		return nil
	}
	switch strings.ToUpper(result.State.Type) {
	case "DELETED", "NON_EXISTING":
		return ErrNewsletterNotFound
	case "SUSPENDED":
		return ErrNewsletterSuspended
	}
	return nil
}

func (cli *Client) sendNewsletterMutation(ctx context.Context, queryID, field string, variables any) error {
	data, err := cli.sendMexIQ(ctx, queryID, variables)
	if err != nil {
		return err
	}
	return decodeNewsletterMutationResponse(data, field)
}

// NewsletterToggleMute changes the mute status of a newsletter.
func (cli *Client) NewsletterToggleMute(ctx context.Context, jid types.JID, mute bool) error {
	return cli.sendNewsletterMutation(ctx, mutationUpdateNewsletterUserSetting, "xwa2_newsletter_update_user_setting", buildNewsletterMuteVariables(jid, mute))
}

// FollowNewsletter makes the user follow (join) a WhatsApp channel.
func (cli *Client) FollowNewsletter(ctx context.Context, jid types.JID) error {
	return cli.sendNewsletterMutation(ctx, mutationFollowNewsletter, "xwa2_newsletter_join_v2", map[string]any{
		"newsletter_id": jid.String(),
	})
}

// UnfollowNewsletter makes the user unfollow (leave) a WhatsApp channel.
func (cli *Client) UnfollowNewsletter(ctx context.Context, jid types.JID) error {
	return cli.sendNewsletterMutation(ctx, mutationUnfollowNewsletter, "xwa2_newsletter_leave_v2", map[string]any{
		"newsletter_id": jid.String(),
	})
}

type GetNewsletterMessagesParams struct {
	Count  int
	Before types.MessageServerID
}

// GetNewsletterMessages gets messages in a WhatsApp channel.
func (cli *Client) GetNewsletterMessages(ctx context.Context, jid types.JID, params *GetNewsletterMessagesParams) ([]*types.NewsletterMessage, error) {
	attrs := waBinary.Attrs{
		"type": "jid",
		"jid":  jid,
	}
	if params != nil {
		if params.Count != 0 {
			attrs["count"] = params.Count
		}
		if params.Before != 0 {
			attrs["before"] = params.Before
		}
	}
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "newsletter",
		Type:      iqGet,
		To:        types.ServerJID,
		Content: []waBinary.Node{{
			Tag:   "messages",
			Attrs: attrs,
		}},
	})
	if err != nil {
		return nil, err
	}
	messages, ok := resp.GetOptionalChildByTag("messages")
	if !ok {
		return nil, &ElementMissingError{Tag: "messages", In: "newsletter messages response"}
	}
	return cli.parseNewsletterMessages(&messages), nil
}

type GetNewsletterUpdatesParams struct {
	Count int
	Since time.Time
	After types.MessageServerID
}

// GetNewsletterMessageUpdates gets updates in a WhatsApp channel.
//
// These are the same kind of updates that NewsletterSubscribeLiveUpdates triggers (reaction and view counts).
func (cli *Client) GetNewsletterMessageUpdates(ctx context.Context, jid types.JID, params *GetNewsletterUpdatesParams) ([]*types.NewsletterMessage, error) {
	attrs := waBinary.Attrs{}
	if params != nil {
		if params.Count != 0 {
			attrs["count"] = params.Count
		}
		if !params.Since.IsZero() {
			attrs["since"] = params.Since.Unix()
		}
		if params.After != 0 {
			attrs["after"] = params.After
		}
	}
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace: "newsletter",
		Type:      iqGet,
		To:        jid,
		Content: []waBinary.Node{{
			Tag:   "message_updates",
			Attrs: attrs,
		}},
	})
	if err != nil {
		return nil, err
	}
	messages, ok := resp.GetOptionalChildByTag("message_updates", "messages")
	if !ok {
		return nil, &ElementMissingError{Tag: "messages", In: "newsletter messages response"}
	}
	return cli.parseNewsletterMessages(&messages), nil
}
