// Operações de dono e administrador de canal: seguidores, administradores,
// mensagens fixadas e insights. Nenhuma delas existe no fork de origem; os IDs e
// as variáveis vêm dos módulos WAWebMex*Newsletter* do WhatsApp Web
// 2.3000.1055901559. Ver WUZAPI_PATCHES.md, "Administração de canal".

package whatsmeow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/polymorfa/hypermeow/types"
)

const (
	mutationCreateNewsletterAdminInvite = "9387141988078609"  // WAWebMexCreateNewsletterAdminInviteJobMutation, output: xwa2_newsletter_admin_invite_create
	mutationAcceptNewsletterAdminInvite = "9580828702035549"  // WAWebMexAcceptNewsletterAdminInviteJobMutation, output: xwa2_newsletter_admin_invite_accept
	mutationRevokeNewsletterAdminInvite = "9656078347839416"  // WAWebMexRevokeNewsletterAdminInviteJobMutation, output: xwa2_newsletter_admin_invite_revoke
	mutationDemoteNewsletterAdmin       = "9880997548630971"  // WAWebMexDemoteNewsletterAdminJobMutation, output: xwa2_newsletter_admin_demote
	mutationChangeNewsletterOwner       = "9546742745432473"  // WAWebMexChangeNewsletterOwnerJobMutation, output: xwa2_newsletter_change_owner
	queryNewsletterPendingAdminInvites  = "28049623068067370" // WAWebMexFetchNewsletterPendingInvitesJobQuery, output: xwa2_newsletter_admin
	queryNewsletterAdminInfo            = "26278439461859188" // WAWebMexFetchNewsletterAdminInfoJobQuery, output: xwa2_newsletter_admin
	mutationPinNewsletterMessages       = "27165709459706559" // WAWebMexNewsletterPinMessagesJobMutation, output: xwa2_newsletter_pin_messages
	mutationUnpinNewsletterMessages     = "28007176042216937" // WAWebMexNewsletterUnpinMessagesJobMutation, output: xwa2_newsletter_unpin_messages
	queryNewsletterInsights             = "9853618868050977"  // WAWebMexFetchNewsletterInsightsJobQuery, output: xwa2_newsletter_admin_insights
)

// ErrNewsletterUserNotLID is returned when an admin operation gets a user JID that is not a LID.
var ErrNewsletterUserNotLID = errors.New("newsletter admin operations need the LID of the user")

// buildNewsletterUserVariables monta as variáveis das mutations de administrador.
// O WhatsApp Web sempre manda o LID do usuário (toUserLidOrThrow).
func buildNewsletterUserVariables(jid, user types.JID) (map[string]any, error) {
	if user.Server != types.HiddenUserServer || user.User == "" {
		return nil, ErrNewsletterUserNotLID
	}
	return map[string]any{
		"newsletter_id": jid.String(),
		"user_id":       user.ToNonAD().String(),
	}, nil
}

func (cli *Client) sendNewsletterUserMutation(ctx context.Context, queryID string, jid, user types.JID) (json.RawMessage, error) {
	variables, err := buildNewsletterUserVariables(jid, user)
	if err != nil {
		return nil, err
	}
	return cli.sendMexIQ(ctx, queryID, variables)
}

func decodeNewsletterAdminInviteExpiration(data json.RawMessage) (time.Time, error) {
	var response struct {
		Invite *struct {
			Expiration flexibleInt `json:"invite_expiration_time"`
		} `json:"xwa2_newsletter_admin_invite_create"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return time.Time{}, fmt.Errorf("decode newsletter admin invite response: %w", err)
	}
	if response.Invite == nil || response.Invite.Expiration <= 0 {
		return time.Time{}, errors.New("newsletter admin invite response is missing invite_expiration_time")
	}
	return time.Unix(int64(response.Invite.Expiration), 0), nil
}

// CreateNewsletterAdminInvite invites a user to be an admin of a channel the
// client owns. It returns when the invite expires.
//
// The invite alone does not notify the user. The WhatsApp clients also send
// the message built by BuildNewsletterAdminInvite to the user.
func (cli *Client) CreateNewsletterAdminInvite(ctx context.Context, jid, user types.JID) (time.Time, error) {
	data, err := cli.sendNewsletterUserMutation(ctx, mutationCreateNewsletterAdminInvite, jid, user)
	if err != nil {
		return time.Time{}, err
	}
	return decodeNewsletterAdminInviteExpiration(data)
}

// NewsletterAdminInviteParams holds the content of the admin invite message.
type NewsletterAdminInviteParams struct {
	Newsletter types.JID
	Name       string
	// Caption is the optional text shown with the invite.
	Caption string
	// JPEGThumbnail is the optional channel picture thumbnail.
	JPEGThumbnail []byte
	// Expiration is the time returned by CreateNewsletterAdminInvite.
	Expiration time.Time
}

// BuildNewsletterAdminInvite builds the message that carries an admin invite
// to the invited user (WAWebGenerateNewsletterAdminInviteMessageProto).
func BuildNewsletterAdminInvite(params NewsletterAdminInviteParams) *waE2E.Message {
	invite := &waE2E.NewsletterAdminInviteMessage{
		NewsletterJID:    proto.String(params.Newsletter.String()),
		NewsletterName:   proto.String(params.Name),
		InviteExpiration: proto.Int64(params.Expiration.Unix()),
	}
	if params.Caption != "" {
		invite.Caption = proto.String(params.Caption)
	}
	if len(params.JPEGThumbnail) > 0 {
		invite.JPEGThumbnail = params.JPEGThumbnail
	}
	return &waE2E.Message{NewsletterAdminInviteMessage: invite}
}

// RevokeNewsletterAdminInvite cancels a pending admin invite.
func (cli *Client) RevokeNewsletterAdminInvite(ctx context.Context, jid, user types.JID) error {
	_, err := cli.sendNewsletterUserMutation(ctx, mutationRevokeNewsletterAdminInvite, jid, user)
	return err
}

// AcceptNewsletterAdminInvite accepts the admin invite the client received for a channel.
func (cli *Client) AcceptNewsletterAdminInvite(ctx context.Context, jid types.JID) error {
	_, err := cli.sendMexIQ(ctx, mutationAcceptNewsletterAdminInvite, map[string]any{
		"newsletter_id": jid.String(),
	})
	return err
}

// DemoteNewsletterAdmin removes the admin role of a user.
func (cli *Client) DemoteNewsletterAdmin(ctx context.Context, jid, user types.JID) error {
	_, err := cli.sendNewsletterUserMutation(ctx, mutationDemoteNewsletterAdmin, jid, user)
	return err
}

// ChangeNewsletterOwner transfers the ownership of a channel to one of its admins.
func (cli *Client) ChangeNewsletterOwner(ctx context.Context, jid, user types.JID) error {
	_, err := cli.sendNewsletterUserMutation(ctx, mutationChangeNewsletterOwner, jid, user)
	return err
}

func decodeNewsletterPendingAdminInvites(data json.RawMessage) ([]types.JID, error) {
	var response struct {
		Admin *struct {
			Pending []*struct {
				User *struct {
					ID string `json:"id"`
				} `json:"user"`
			} `json:"pending_admin_invites"`
		} `json:"xwa2_newsletter_admin"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode newsletter pending invites response: %w", err)
	}
	invited := []types.JID{}
	if response.Admin == nil {
		return invited, nil
	}
	for _, item := range response.Admin.Pending {
		if item == nil || item.User == nil || item.User.ID == "" {
			continue
		}
		jid, err := types.ParseJID(item.User.ID)
		if err != nil {
			continue
		}
		invited = append(invited, jid)
	}
	return invited, nil
}

// GetNewsletterPendingAdminInvites lists the users with a pending admin invite.
func (cli *Client) GetNewsletterPendingAdminInvites(ctx context.Context, jid types.JID) ([]types.JID, error) {
	data, err := cli.sendMexIQ(ctx, queryNewsletterPendingAdminInvites, map[string]any{
		"newsletter_id": jid.String(),
	})
	if err != nil {
		return nil, err
	}
	return decodeNewsletterPendingAdminInvites(data)
}

func decodeNewsletterAdminCount(data json.RawMessage) (int, error) {
	var response struct {
		Admin *struct {
			Count flexibleInt `json:"admin_count"`
		} `json:"xwa2_newsletter_admin"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return 0, fmt.Errorf("decode newsletter admin info response: %w", err)
	}
	if response.Admin == nil {
		return 0, errors.New("newsletter response is missing xwa2_newsletter_admin")
	}
	return int(response.Admin.Count), nil
}

// GetNewsletterAdminCount gets the number of admins of a channel, the owner included.
func (cli *Client) GetNewsletterAdminCount(ctx context.Context, jid types.JID) (int, error) {
	data, err := cli.sendMexIQ(ctx, queryNewsletterAdminInfo, map[string]any{
		"newsletter_id": jid.String(),
	})
	if err != nil {
		return 0, err
	}
	return decodeNewsletterAdminCount(data)
}

func decodeNewsletterFollowers(data json.RawMessage) ([]*types.NewsletterFollower, error) {
	var response struct {
		Result *struct {
			Followers *struct {
				Edges []*struct {
					Node *struct {
						ID           string `json:"id"`
						DisplayName  string `json:"display_name"`
						PN           string `json:"pn"`
						UsernameInfo *struct {
							Username string `json:"username"`
						} `json:"username_info"`
					} `json:"node"`
					Role       types.NewsletterRole `json:"role"`
					FollowTime flexibleInt          `json:"follow_time"`
				} `json:"edges"`
			} `json:"followers"`
		} `json:"xwa2_newsletter_followers"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode newsletter followers response: %w", err)
	}
	followers := []*types.NewsletterFollower{}
	if response.Result == nil || response.Result.Followers == nil {
		return followers, nil
	}
	for _, edge := range response.Result.Followers.Edges {
		if edge == nil || edge.Node == nil || edge.Node.ID == "" {
			continue
		}
		id, err := types.ParseJID(edge.Node.ID)
		if err != nil {
			continue
		}
		follower := &types.NewsletterFollower{
			ID:          id,
			DisplayName: edge.Node.DisplayName,
			Role:        edge.Role,
		}
		if edge.Node.PN != "" {
			if pn, err := types.ParseJID(edge.Node.PN); err == nil {
				follower.PhoneNumber = pn
			}
		}
		if edge.Node.UsernameInfo != nil {
			follower.Username = edge.Node.UsernameInfo.Username
		}
		if edge.FollowTime > 0 {
			follower.FollowTime = time.Unix(int64(edge.FollowTime), 0)
		}
		followers = append(followers, follower)
	}
	return followers, nil
}

// GetNewsletterFollowers lists up to count followers of a channel the client
// owns or administers. WhatsApp only shows the phone number of the followers
// the account already knows.
func (cli *Client) GetNewsletterFollowers(ctx context.Context, jid types.JID, count int) ([]*types.NewsletterFollower, error) {
	data, err := cli.sendMexIQ(ctx, queryNewsletterSubscribers, map[string]any{
		"input": map[string]any{
			"newsletter_id": jid.String(),
			"count":         count,
		},
	})
	if err != nil {
		return nil, err
	}
	return decodeNewsletterFollowers(data)
}

// buildNewsletterPinVariables monta as variáveis de fixar e desafixar. O
// WhatsApp Web manda os ids de servidor como string (WAWebNewsletterPinMessageAction).
func buildNewsletterPinVariables(jid types.JID, serverIDs []types.MessageServerID) (map[string]any, error) {
	if len(serverIDs) == 0 {
		return nil, errors.New("no newsletter messages to pin or unpin")
	}
	ids := make([]string, len(serverIDs))
	for i, serverID := range serverIDs {
		if serverID <= 0 {
			return nil, fmt.Errorf("invalid newsletter message server ID %d", serverID)
		}
		ids[i] = strconv.Itoa(serverID)
	}
	return map[string]any{
		"newsletter_id": jid.String(),
		"input":         map[string]any{"message_ids": ids},
	}, nil
}

func decodeNewsletterPinnedMessages(data json.RawMessage, field string) ([]types.NewsletterPinnedMessage, error) {
	var response map[string]*struct {
		ThreadMeta *struct {
			Pinned []*struct {
				MessageID flexibleInt `json:"message_id"`
				ExpiryTS  flexibleInt `json:"expiry_ts"`
			} `json:"pinned_messages"`
		} `json:"thread_metadata"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", field, err)
	}
	result := response[field]
	if result == nil {
		return nil, fmt.Errorf("newsletter response is missing %s", field)
	}
	pinned := []types.NewsletterPinnedMessage{}
	if result.ThreadMeta == nil {
		return pinned, nil
	}
	for _, item := range result.ThreadMeta.Pinned {
		if item == nil || item.MessageID <= 0 {
			continue
		}
		message := types.NewsletterPinnedMessage{ServerID: int(item.MessageID)}
		if item.ExpiryTS > 0 {
			message.Expiration = time.Unix(int64(item.ExpiryTS), 0)
		}
		pinned = append(pinned, message)
	}
	return pinned, nil
}

func (cli *Client) setNewsletterPins(ctx context.Context, queryID, field string, jid types.JID, serverIDs []types.MessageServerID) ([]types.NewsletterPinnedMessage, error) {
	variables, err := buildNewsletterPinVariables(jid, serverIDs)
	if err != nil {
		return nil, err
	}
	data, err := cli.sendMexIQ(ctx, queryID, variables)
	if err != nil {
		return nil, err
	}
	return decodeNewsletterPinnedMessages(data, field)
}

// PinNewsletterMessages pins messages of a channel. It returns the messages
// that are pinned after the change.
func (cli *Client) PinNewsletterMessages(ctx context.Context, jid types.JID, serverIDs []types.MessageServerID) ([]types.NewsletterPinnedMessage, error) {
	return cli.setNewsletterPins(ctx, mutationPinNewsletterMessages, "xwa2_newsletter_pin_messages", jid, serverIDs)
}

// UnpinNewsletterMessages unpins messages of a channel. It returns the
// messages that are still pinned after the change.
func (cli *Client) UnpinNewsletterMessages(ctx context.Context, jid types.JID, serverIDs []types.MessageServerID) ([]types.NewsletterPinnedMessage, error) {
	return cli.setNewsletterPins(ctx, mutationUnpinNewsletterMessages, "xwa2_newsletter_unpin_messages", jid, serverIDs)
}

// NewsletterInsightMetric is one metric requested from the channel insights
// (WAWebNewsletterInsight*Processors). ID is chosen by the caller and comes
// back in the result, to match each request with its values.
type NewsletterInsightMetric struct {
	ID      int                      `json:"id"`
	Type    string                   `json:"type"`
	GroupBy NewsletterInsightGroupBy `json:"group_by"`
	// Surface is omitted for the channel itself. The WhatsApp Web also uses
	// "ALL" and "CHANNEL_STATUS".
	Surface string `json:"surface,omitempty"`
}

type NewsletterInsightGroupBy struct {
	NumberOfDays int  `json:"number_of_days"`
	Country      bool `json:"country,omitempty"`
	Role         bool `json:"role,omitempty"`
}

// Tipos de métrica que o WhatsApp Web pede.
const (
	NewsletterInsightFollowers         = "FOLLOWER"
	NewsletterInsightNetFollows        = "NET_FOLLOWS"
	NewsletterInsightFollows           = "FOLLOWS"
	NewsletterInsightUnfollows         = "UNFOLLOWS"
	NewsletterInsightUniqueVisitors    = "UNIQUE_VISITORS"
	NewsletterInsightNewUniqueVisitors = "NEW_UNIQUE_VISITORS"
)

func decodeNewsletterInsights(data json.RawMessage) (*types.NewsletterInsights, error) {
	var response struct {
		Insights *struct {
			LastUpdateTime flexibleInt `json:"last_update_time"`
			MetricsStatus  string      `json:"metrics_status"`
			Result         []*struct {
				ID     flexibleInt `json:"id"`
				Values []*struct {
					Value     flexibleFloat `json:"value"`
					Country   string        `json:"country"`
					Role      string        `json:"role"`
					Timestamp flexibleInt   `json:"timestamp"`
				} `json:"values"`
			} `json:"result"`
		} `json:"xwa2_newsletter_admin_insights"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode newsletter insights response: %w", err)
	}
	if response.Insights == nil {
		return nil, errors.New("newsletter response is missing xwa2_newsletter_admin_insights")
	}
	insights := &types.NewsletterInsights{
		Status:  response.Insights.MetricsStatus,
		Metrics: []types.NewsletterInsightResult{},
	}
	if response.Insights.LastUpdateTime > 0 {
		insights.LastUpdate = time.Unix(int64(response.Insights.LastUpdateTime), 0)
	}
	for _, metric := range response.Insights.Result {
		if metric == nil {
			continue
		}
		result := types.NewsletterInsightResult{ID: int(metric.ID), Values: []types.NewsletterInsightValue{}}
		for _, value := range metric.Values {
			if value == nil {
				continue
			}
			item := types.NewsletterInsightValue{
				Value:   float64(value.Value),
				Country: value.Country,
				Role:    strings.ToLower(value.Role),
			}
			if value.Timestamp > 0 {
				item.Timestamp = time.Unix(int64(value.Timestamp), 0)
			}
			result.Values = append(result.Values, item)
		}
		insights.Metrics = append(insights.Metrics, result)
	}
	return insights, nil
}

// GetNewsletterInsights gets audience metrics of a channel the client owns or administers.
func (cli *Client) GetNewsletterInsights(ctx context.Context, jid types.JID, metrics []NewsletterInsightMetric) (*types.NewsletterInsights, error) {
	if len(metrics) == 0 {
		return nil, errors.New("no newsletter insight metrics requested")
	}
	data, err := cli.sendMexIQ(ctx, queryNewsletterInsights, map[string]any{
		"input": map[string]any{
			"newsletter_id": jid.String(),
			"metrics":       metrics,
		},
	})
	if err != nil {
		return nil, err
	}
	return decodeNewsletterInsights(data)
}

// flexibleInt lê um inteiro que o servidor manda como número ou como string.
type flexibleInt int64

func (value *flexibleInt) UnmarshalJSON(data []byte) error {
	text := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if text == "" || text == "null" {
		*value = 0
		return nil
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		float, floatErr := strconv.ParseFloat(text, 64)
		if floatErr != nil {
			return fmt.Errorf("invalid integer %q", text)
		}
		parsed = int64(float)
	}
	*value = flexibleInt(parsed)
	return nil
}

// flexibleFloat lê um número que o servidor manda como número ou como string.
type flexibleFloat float64

func (value *flexibleFloat) UnmarshalJSON(data []byte) error {
	text := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if text == "" || text == "null" {
		*value = 0
		return nil
	}
	parsed, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return fmt.Errorf("invalid number %q", text)
	}
	*value = flexibleFloat(parsed)
	return nil
}
