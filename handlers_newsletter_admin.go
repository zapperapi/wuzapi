package main

// Newsletter (WhatsApp channel) owner and admin handlers.
//
//   GET  /newsletter/followers     -> followers of a channel
//   GET  /newsletter/admins        -> number of admins and pending admin invites
//   POST /newsletter/admin/invite  -> invite a user to be an admin
//   POST /newsletter/admin/revoke  -> cancel a pending admin invite
//   POST /newsletter/admin/accept  -> accept the admin invite the account received
//   POST /newsletter/admin/demote  -> remove the admin role of a user
//   POST /newsletter/owner         -> transfer the ownership of a channel
//   POST /newsletter/pin           -> pin or unpin messages
//   POST /newsletter/insights      -> audience metrics
//   POST /newsletter/poll          -> publish a poll or a quiz
//   POST /newsletter/question      -> publish a question
//
// Kept in a dedicated file to minimise rebase conflicts against upstream.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/polymorfa/hypermeow/types"
	"github.com/rs/zerolog/log"
)

const (
	defaultNewsletterFollowerCount = 100
	maxNewsletterFollowerCount     = 1000
	maxNewsletterPollOptions       = 12
	minNewsletterPollOptions       = 2
)

// newsletterUserJSON identifies a WhatsApp user in the channel responses. The
// phone number is empty when the account does not know it.
type newsletterUserJSON struct {
	LID string `json:"LID"`
	PN  string `json:"PN"`
}

func newsletterUser(ctx context.Context, client *whatsmeow.Client, lid, pn types.JID) newsletterUserJSON {
	user := newsletterUserJSON{LID: lid.String()}
	if !pn.IsEmpty() {
		user.PN = pn.ToNonAD().String()
	} else if known, err := getCachedPNForLID(ctx, client, lid); err == nil {
		user.PN = known.ToNonAD().String()
	}
	return user
}

// errNewsletterUserLIDUnknown is returned when the LID of a phone number is not known.
var errNewsletterUserLIDUnknown = errors.New("LID not found for this number")

// resolveNewsletterUserLID converts a phone number or a LID to the LID that the
// channel admin operations need. A phone number is looked up in the session
// store first and in WhatsApp after that.
func resolveNewsletterUserLID(ctx context.Context, client *whatsmeow.Client, value string) (types.JID, error) {
	jid, ok := parseJID(strings.TrimSpace(value))
	if !ok || jid.User == "" {
		return types.EmptyJID, newsletterBadRequest{"could not parse User"}
	}
	switch jid.Server {
	case types.HiddenUserServer:
		return jid.ToNonAD(), nil
	case types.DefaultUserServer:
	default:
		return types.EmptyJID, newsletterBadRequest{"User must be a phone number or a LID"}
	}

	jid = jid.ToNonAD()
	if client.Store != nil && client.Store.LIDs != nil {
		if lid, err := client.Store.LIDs.GetLIDForPN(ctx, jid); err == nil && !lid.IsEmpty() {
			return lid.ToNonAD(), nil
		}
	}
	info, err := client.GetUserInfo(ctx, []types.JID{jid})
	if err != nil {
		return types.EmptyJID, fmt.Errorf("could not look up the LID of %s: %w", jid.User, err)
	}
	if user, found := info[jid]; found && !user.LID.IsEmpty() {
		return user.LID.ToNonAD(), nil
	}
	return types.EmptyJID, errNewsletterUserLIDUnknown
}

// respondNewsletterUserError answers a failure to identify the user of an admin operation.
func (s *server) respondNewsletterUserError(w http.ResponseWriter, r *http.Request, err error) {
	var badRequest newsletterBadRequest
	switch {
	case errors.As(err, &badRequest):
		s.Respond(w, r, http.StatusBadRequest, err)
	case errors.Is(err, errNewsletterUserLIDUnknown):
		s.Respond(w, r, http.StatusNotFound, err)
	default:
		s.respondNewsletterError(w, r, "identify the user", err)
	}
}

// newsletterFromQuery reads the channel JID of a GET route. On failure it
// writes the response and returns ok=false.
func (s *server) newsletterFromQuery(w http.ResponseWriter, r *http.Request) (types.JID, bool) {
	value := r.URL.Query().Get("newsletterJID")
	if value == "" {
		s.Respond(w, r, http.StatusBadRequest, errors.New("missing newsletterJID parameter"))
		return types.EmptyJID, false
	}
	jid, ok := parseNewsletterJID(value)
	if !ok {
		s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
		return types.EmptyJID, false
	}
	return jid, true
}

// parseNewsletterFollowerCount reads the optional count of followers to list.
func parseNewsletterFollowerCount(value string) (int, error) {
	if value == "" {
		return defaultNewsletterFollowerCount, nil
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 1 || count > maxNewsletterFollowerCount {
		return 0, fmt.Errorf("count must be a number from 1 to %d", maxNewsletterFollowerCount)
	}
	return count, nil
}

// GetNewsletterFollowers lists the followers of a channel the account owns or administers.
func (s *server) GetNewsletterFollowers() http.HandlerFunc {

	type followerJSON struct {
		newsletterUserJSON
		DisplayName string `json:"DisplayName"`
		Username    string `json:"Username"`
		Role        string `json:"Role"`
		FollowTime  int64  `json:"FollowTime"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		jid, ok := s.newsletterFromQuery(w, r)
		if !ok {
			return
		}

		count, err := parseNewsletterFollowerCount(r.URL.Query().Get("count"))
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		followers, err := client.GetNewsletterFollowers(r.Context(), jid, count)
		if err != nil {
			s.respondNewsletterError(w, r, "get newsletter followers", err)
			return
		}

		list := make([]followerJSON, 0, len(followers))
		for _, follower := range followers {
			item := followerJSON{
				newsletterUserJSON: newsletterUser(r.Context(), client, follower.ID, follower.PhoneNumber),
				DisplayName:        follower.DisplayName,
				Username:           follower.Username,
				Role:               string(follower.Role),
			}
			if !follower.FollowTime.IsZero() {
				item.FollowTime = follower.FollowTime.Unix()
			}
			list = append(list, item)
		}

		s.respondJSON(w, r, map[string]interface{}{"Followers": list})
	}
}

// GetNewsletterAdmins returns the number of admins of a channel and the users
// with a pending admin invite. WhatsApp does not list the admins themselves
// here: they are the followers with the role admin or owner.
func (s *server) GetNewsletterAdmins() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		jid, ok := s.newsletterFromQuery(w, r)
		if !ok {
			return
		}

		count, err := client.GetNewsletterAdminCount(r.Context(), jid)
		if err != nil {
			s.respondNewsletterError(w, r, "get newsletter admins", err)
			return
		}

		invited, err := client.GetNewsletterPendingAdminInvites(r.Context(), jid)
		if err != nil {
			s.respondNewsletterError(w, r, "get newsletter admin invites", err)
			return
		}

		pending := make([]newsletterUserJSON, 0, len(invited))
		for _, user := range invited {
			pending = append(pending, newsletterUser(r.Context(), client, user, types.EmptyJID))
		}

		s.respondJSON(w, r, map[string]interface{}{"AdminCount": count, "PendingInvites": pending})
	}
}

type newsletterUserStruct struct {
	NewsletterJID string `json:"newsletterjid"`
	User          string `json:"user"`
	Caption       string `json:"caption"`
}

// newsletterUserAction runs an admin operation on one user of a channel.
func (s *server) newsletterUserAction(action string, run func(ctx context.Context, client *whatsmeow.Client, jid, user types.JID, body newsletterUserStruct) (map[string]interface{}, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t newsletterUserStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		jid, ok := parseNewsletterJID(t.NewsletterJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
			return
		}

		if strings.TrimSpace(t.User) == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing User in Payload"))
			return
		}

		user, err := resolveNewsletterUserLID(r.Context(), client, t.User)
		if err != nil {
			s.respondNewsletterUserError(w, r, err)
			return
		}

		result, err := run(r.Context(), client, jid, user, t)
		if err != nil {
			s.respondNewsletterError(w, r, action, err)
			return
		}
		if result == nil {
			result = map[string]interface{}{}
		}
		result["Details"] = "Success"
		result["User"] = newsletterUser(r.Context(), client, user, types.EmptyJID)

		s.respondJSON(w, r, result)
	}
}

// InviteNewsletterAdmin invites a user to be an admin of a channel the account
// owns. Like the WhatsApp clients, it creates the invite and then sends the
// invite message to the user: without the message the user has no way to accept.
func (s *server) InviteNewsletterAdmin() http.HandlerFunc {
	return s.newsletterUserAction("invite newsletter admin",
		func(ctx context.Context, client *whatsmeow.Client, jid, user types.JID, body newsletterUserStruct) (map[string]interface{}, error) {
			expiration, err := client.CreateNewsletterAdminInvite(ctx, jid, user)
			if err != nil {
				return nil, err
			}

			result := map[string]interface{}{"InviteExpiration": expiration.Unix()}

			name := ""
			if info, infoErr := client.GetNewsletterInfo(ctx, jid); infoErr == nil && info != nil {
				name = info.ThreadMeta.Name.Text
			}
			message := whatsmeow.BuildNewsletterAdminInvite(whatsmeow.NewsletterAdminInviteParams{
				Newsletter: jid,
				Name:       name,
				Caption:    strings.TrimSpace(body.Caption),
				Expiration: expiration,
			})
			resp, sendErr := client.SendMessage(ctx, user, message)
			if sendErr != nil {
				// O convite existe; só o aviso ao usuário falhou. Quem chamou
				// decide entre reenviar o convite e revogá-lo.
				log.Error().Err(sendErr).Str("newsletter", jid.String()).Msg("Newsletter admin invite created, but the invite message was not sent")
				result["MessageSent"] = false
				result["MessageError"] = sendErr.Error()
				return result, nil
			}
			result["MessageSent"] = true
			result["MessageId"] = resp.ID
			return result, nil
		})
}

// RevokeNewsletterAdminInvite cancels a pending admin invite.
func (s *server) RevokeNewsletterAdminInvite() http.HandlerFunc {
	return s.newsletterUserAction("revoke newsletter admin invite",
		func(ctx context.Context, client *whatsmeow.Client, jid, user types.JID, _ newsletterUserStruct) (map[string]interface{}, error) {
			return nil, client.RevokeNewsletterAdminInvite(ctx, jid, user)
		})
}

// DemoteNewsletterAdmin removes the admin role of a user.
func (s *server) DemoteNewsletterAdmin() http.HandlerFunc {
	return s.newsletterUserAction("demote newsletter admin",
		func(ctx context.Context, client *whatsmeow.Client, jid, user types.JID, _ newsletterUserStruct) (map[string]interface{}, error) {
			return nil, client.DemoteNewsletterAdmin(ctx, jid, user)
		})
}

// ChangeNewsletterOwner transfers the ownership of a channel to one of its admins.
func (s *server) ChangeNewsletterOwner() http.HandlerFunc {
	return s.newsletterUserAction("change newsletter owner",
		func(ctx context.Context, client *whatsmeow.Client, jid, user types.JID, _ newsletterUserStruct) (map[string]interface{}, error) {
			return nil, client.ChangeNewsletterOwner(ctx, jid, user)
		})
}

// AcceptNewsletterAdminInvite accepts the admin invite the account received for a channel.
func (s *server) AcceptNewsletterAdminInvite() http.HandlerFunc {
	return s.newsletterAction("accept newsletter admin invite", "Newsletter admin invite accepted successfully",
		func(r *http.Request, client *whatsmeow.Client, jid types.JID, _ newsletterJIDStruct) error {
			return client.AcceptNewsletterAdminInvite(r.Context(), jid)
		})
}

type newsletterPinStruct struct {
	NewsletterJID string `json:"newsletterjid"`
	ServerIDs     []int  `json:"serverids"`
	Pin           *bool  `json:"pin"`
}

// validateNewsletterPin checks the body of /newsletter/pin.
func validateNewsletterPin(t newsletterPinStruct) error {
	if t.Pin == nil {
		return errors.New("missing pin in Payload")
	}
	if len(t.ServerIDs) == 0 {
		return errors.New("missing serverids in Payload")
	}
	for _, serverID := range t.ServerIDs {
		if serverID <= 0 {
			return errors.New("serverids must be positive numbers")
		}
	}
	return nil
}

// PinNewsletterMessages pins or unpins messages of a channel. The response
// lists the messages that are pinned after the change.
func (s *server) PinNewsletterMessages() http.HandlerFunc {

	type pinnedJSON struct {
		ServerID   int   `json:"ServerID"`
		Expiration int64 `json:"Expiration"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t newsletterPinStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		jid, ok := parseNewsletterJID(t.NewsletterJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
			return
		}

		if err := validateNewsletterPin(t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		var pinned []types.NewsletterPinnedMessage
		var err error
		action := "pin newsletter messages"
		if *t.Pin {
			pinned, err = client.PinNewsletterMessages(r.Context(), jid, t.ServerIDs)
		} else {
			action = "unpin newsletter messages"
			pinned, err = client.UnpinNewsletterMessages(r.Context(), jid, t.ServerIDs)
		}
		if err != nil {
			s.respondNewsletterError(w, r, action, err)
			return
		}

		list := make([]pinnedJSON, 0, len(pinned))
		for _, message := range pinned {
			item := pinnedJSON{ServerID: message.ServerID}
			if !message.Expiration.IsZero() {
				item.Expiration = message.Expiration.Unix()
			}
			list = append(list, item)
		}

		s.respondJSON(w, r, map[string]interface{}{"PinnedMessages": list})
	}
}

type newsletterInsightsStruct struct {
	NewsletterJID string                              `json:"newsletterjid"`
	Metrics       []whatsmeow.NewsletterInsightMetric `json:"metrics"`
}

// validateNewsletterInsightMetrics checks the metrics of /newsletter/insights.
func validateNewsletterInsightMetrics(metrics []whatsmeow.NewsletterInsightMetric) error {
	if len(metrics) == 0 {
		return errors.New("missing metrics in Payload")
	}
	seen := make(map[int]bool, len(metrics))
	for _, metric := range metrics {
		if metric.Type == "" {
			return errors.New("every metric needs a type")
		}
		if metric.GroupBy.NumberOfDays < 1 {
			return errors.New("every metric needs group_by.number_of_days")
		}
		if seen[metric.ID] {
			return fmt.Errorf("metric id %d is repeated", metric.ID)
		}
		seen[metric.ID] = true
	}
	return nil
}

// GetNewsletterInsights returns audience metrics of a channel the account owns
// or administers. The caller chooses the metrics, and each result comes back
// with the id of its request.
func (s *server) GetNewsletterInsights() http.HandlerFunc {

	type valueJSON struct {
		Value     float64 `json:"Value"`
		Country   string  `json:"Country,omitempty"`
		Role      string  `json:"Role,omitempty"`
		Timestamp int64   `json:"Timestamp,omitempty"`
	}
	type metricJSON struct {
		ID     int         `json:"ID"`
		Values []valueJSON `json:"Values"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t newsletterInsightsStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		jid, ok := parseNewsletterJID(t.NewsletterJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
			return
		}

		if err := validateNewsletterInsightMetrics(t.Metrics); err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		insights, err := client.GetNewsletterInsights(r.Context(), jid, t.Metrics)
		if err != nil {
			s.respondNewsletterError(w, r, "get newsletter insights", err)
			return
		}

		metrics := make([]metricJSON, 0, len(insights.Metrics))
		for _, metric := range insights.Metrics {
			item := metricJSON{ID: metric.ID, Values: make([]valueJSON, 0, len(metric.Values))}
			for _, value := range metric.Values {
				entry := valueJSON{Value: value.Value, Country: value.Country, Role: value.Role}
				if !value.Timestamp.IsZero() {
					entry.Timestamp = value.Timestamp.Unix()
				}
				item.Values = append(item.Values, entry)
			}
			metrics = append(metrics, item)
		}

		var lastUpdate int64
		if !insights.LastUpdate.IsZero() {
			lastUpdate = insights.LastUpdate.Unix()
		}

		s.respondJSON(w, r, map[string]interface{}{
			"Status":     insights.Status,
			"LastUpdate": lastUpdate,
			"Metrics":    metrics,
		})
	}
}

type newsletterPollStruct struct {
	NewsletterJID string   `json:"newsletterjid"`
	Name          string   `json:"name"`
	Options       []string `json:"options"`
	// SingleChoice lets the follower choose only one option. A quiz is always single choice.
	SingleChoice bool `json:"singlechoice"`
	// CorrectOption turns the poll into a quiz: the index, from 0, of the correct option.
	CorrectOption *int   `json:"correctoption"`
	Id            string `json:"id"`
}

// buildNewsletterPollMessage validates the body of /newsletter/poll and builds
// the poll, or the quiz when the body has a correct option.
func buildNewsletterPollMessage(t newsletterPollStruct) (*waE2E.Message, error) {
	name := strings.TrimSpace(t.Name)
	if name == "" {
		return nil, errors.New("missing name in Payload")
	}
	if len(t.Options) < minNewsletterPollOptions || len(t.Options) > maxNewsletterPollOptions {
		return nil, fmt.Errorf("options must have from %d to %d items", minNewsletterPollOptions, maxNewsletterPollOptions)
	}
	options := make([]string, len(t.Options))
	seen := make(map[string]bool, len(t.Options))
	for i, option := range t.Options {
		option = strings.TrimSpace(option)
		if option == "" {
			return nil, errors.New("options must not be empty")
		}
		if seen[option] {
			return nil, errors.New("options must not repeat")
		}
		seen[option] = true
		options[i] = option
	}
	if t.CorrectOption != nil {
		message, err := whatsmeow.BuildNewsletterQuiz(name, options, *t.CorrectOption)
		if err != nil {
			return nil, errors.New("correctoption must be the index of one of the options")
		}
		return message, nil
	}
	return whatsmeow.BuildNewsletterPoll(name, options, t.SingleChoice), nil
}

// publishToNewsletter sends a message to a channel and answers with its ids.
func (s *server) publishToNewsletter(w http.ResponseWriter, r *http.Request, client *whatsmeow.Client, jid types.JID, id, action string, message *waE2E.Message) {
	if id == "" {
		id = client.GenerateMessageID()
	}
	resp, err := client.SendMessage(r.Context(), jid, message, whatsmeow.SendRequestExtra{ID: id})
	if err != nil {
		s.respondNewsletterError(w, r, action, err)
		return
	}
	s.respondJSON(w, r, map[string]interface{}{
		"Details":   "Sent",
		"Id":        resp.ID,
		"ServerID":  resp.ServerID,
		"Timestamp": resp.Timestamp.Unix(),
	})
}

// SendNewsletterPoll publishes a poll in a channel, or a quiz when the body has
// a correct option.
func (s *server) SendNewsletterPoll() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t newsletterPollStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		jid, ok := parseNewsletterJID(t.NewsletterJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
			return
		}

		message, err := buildNewsletterPollMessage(t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		s.publishToNewsletter(w, r, client, jid, t.Id, "publish newsletter poll", message)
	}
}

// SendNewsletterQuestion publishes a question in a channel: a text the
// followers can answer.
func (s *server) SendNewsletterQuestion() http.HandlerFunc {

	type questionStruct struct {
		NewsletterJID string `json:"newsletterjid"`
		Text          string `json:"text"`
		Id            string `json:"id"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t questionStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		jid, ok := parseNewsletterJID(t.NewsletterJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
			return
		}

		text := strings.TrimSpace(t.Text)
		if text == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing text in Payload"))
			return
		}

		s.publishToNewsletter(w, r, client, jid, t.Id, "publish newsletter question", whatsmeow.BuildNewsletterQuestion(text))
	}
}
