package main

// Newsletter (WhatsApp channel) handlers.
//
// whatsmeow exposes the calls, but upstream wuzapi only lists the channels:
//   POST /newsletter/create    -> create a channel
//   GET  /newsletter/info      -> channel data, by JID (followed channels) or by invite
//   POST /newsletter/update    -> change the name, the description or the picture of a channel
//   POST /newsletter/follow    -> follow a channel
//   POST /newsletter/unfollow  -> stop following a channel
//   POST /newsletter/mute      -> mute or unmute the updates of a channel
//   POST /newsletter/delete    -> delete an owned channel
//
// Kept in a dedicated file to minimise rebase conflicts against upstream.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/types"
	"github.com/rs/zerolog/log"
	"github.com/vincent-petithory/dataurl"
)

// parseNewsletterJID accepts a channel id with or without the @newsletter suffix.
func parseNewsletterJID(value string) (types.JID, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return types.EmptyJID, false
	}
	if !strings.ContainsRune(value, '@') {
		value += "@" + types.NewsletterServer
	}
	jid, err := types.ParseJID(value)
	if err != nil || jid.Server != types.NewsletterServer || jid.User == "" || jid.Device != 0 {
		return types.EmptyJID, false
	}
	for _, character := range jid.User {
		if character < '0' || character > '9' {
			return types.EmptyJID, false
		}
	}
	return jid, true
}

// newsletterErrorStatus maps a channel error to the HTTP status of the response.
// A channel that was deleted or never existed is 404; anything else is a refusal
// from WhatsApp and keeps the usual 500.
func newsletterErrorStatus(err error) int {
	if errors.Is(err, whatsmeow.ErrNewsletterNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func (s *server) respondNewsletterError(w http.ResponseWriter, r *http.Request, action string, err error) {
	msg := fmt.Sprintf("failed to %s: %v", action, err)
	log.Error().Msg(msg)
	s.Respond(w, r, newsletterErrorStatus(err), errors.New(msg))
}

type newsletterJIDStruct struct {
	NewsletterJID string `json:"newsletterjid"`
	Mute          *bool  `json:"mute"`
}

// newsletterFromBody decodes the body and parses its channel JID. On failure it
// writes the response and returns ok=false.
func (s *server) newsletterFromBody(w http.ResponseWriter, r *http.Request) (newsletterJIDStruct, types.JID, bool) {
	var t newsletterJIDStruct
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
		return t, types.EmptyJID, false
	}
	jid, ok := parseNewsletterJID(t.NewsletterJID)
	if !ok {
		s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
		return t, types.EmptyJID, false
	}
	return t, jid, true
}

// CreateNewsletter creates a channel owned by the connected account.
func (s *server) CreateNewsletter() http.HandlerFunc {

	type createNewsletterStruct struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t createNewsletterStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		t.Name = strings.TrimSpace(t.Name)
		if t.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Name in Payload"))
			return
		}

		info, err := client.CreateNewsletter(r.Context(), whatsmeow.CreateNewsletterParams{
			Name:        t.Name,
			Description: t.Description,
		})
		if err != nil {
			s.respondNewsletterError(w, r, "create newsletter", err)
			return
		}
		if info == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("failed to create newsletter: empty response"))
			return
		}

		s.respondJSON(w, r, info)
	}
}

// GetNewsletterInfo returns the data of a channel. The JID lookup only works for
// channels the account follows or owns; the invite lookup works for any channel.
func (s *server) GetNewsletterInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		query := r.URL.Query()
		jidValue := query.Get("newsletterJID")
		invite := strings.TrimSpace(query.Get("invite"))

		var info *types.NewsletterMetadata
		var err error
		switch {
		case jidValue != "":
			jid, ok := parseNewsletterJID(jidValue)
			if !ok {
				s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
				return
			}
			info, err = client.GetNewsletterInfo(r.Context(), jid)
		case invite != "":
			info, err = client.GetNewsletterInfoWithInvite(r.Context(), invite)
		default:
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing newsletterJID or invite parameter"))
			return
		}

		if err != nil {
			s.respondNewsletterError(w, r, "get newsletter info", err)
			return
		}
		if info == nil {
			s.Respond(w, r, http.StatusNotFound, errors.New("failed to get newsletter info: newsletter not found"))
			return
		}

		s.respondJSON(w, r, info)
	}
}

type updateNewsletterStruct struct {
	NewsletterJID string  `json:"newsletterjid"`
	Name          *string `json:"name"`
	Description   *string `json:"description"`
	// Image is a JPEG as a data URL. An empty string removes the picture.
	Image *string `json:"image"`
}

// buildUpdateNewsletterParams validates the body of /newsletter/update and
// converts it to the library parameters. A field left out is not changed.
func buildUpdateNewsletterParams(t updateNewsletterStruct) (whatsmeow.UpdateNewsletterParams, error) {
	var params whatsmeow.UpdateNewsletterParams

	if t.Name != nil {
		name := strings.TrimSpace(*t.Name)
		if name == "" {
			return params, errors.New("name must not be empty")
		}
		params.Name = &name
	}

	if t.Description != nil {
		description := strings.TrimSpace(*t.Description)
		params.Description = &description
	}

	if t.Image != nil {
		picture := []byte{}
		if *t.Image != "" {
			if !strings.HasPrefix(*t.Image, "data:image") {
				return params, errors.New("image data should start with \"data:image/\"")
			}
			dataURL, err := dataurl.DecodeString(*t.Image)
			if err != nil {
				return params, errors.New("could not decode base64 encoded data from payload")
			}
			picture = dataURL.Data
			if len(picture) < 3 || picture[0] != 0xFF || picture[1] != 0xD8 || picture[2] != 0xFF {
				return params, errors.New("image must be in JPEG format. WhatsApp only accepts JPEG images for channel pictures")
			}
		}
		params.Picture = &picture
	}

	if params.Name == nil && params.Description == nil && params.Picture == nil {
		return params, errors.New("missing name, description or image in Payload")
	}
	return params, nil
}

// UpdateNewsletter changes the name, the description or the picture of a
// channel the connected account owns or administers.
func (s *server) UpdateNewsletter() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t updateNewsletterStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		jid, ok := parseNewsletterJID(t.NewsletterJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Newsletter JID"))
			return
		}

		params, err := buildUpdateNewsletterParams(t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		info, err := client.UpdateNewsletter(r.Context(), jid, params)
		if err != nil {
			s.respondNewsletterError(w, r, "update newsletter", err)
			return
		}

		s.respondJSON(w, r, info)
	}
}

// newsletterAction runs a channel operation that has no data to return.
func (s *server) newsletterAction(action, details string, run func(r *http.Request, client *whatsmeow.Client, jid types.JID, body newsletterJIDStruct) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		body, jid, ok := s.newsletterFromBody(w, r)
		if !ok {
			return
		}

		if err := run(r, client, jid, body); err != nil {
			var badRequest newsletterBadRequest
			if errors.As(err, &badRequest) {
				s.Respond(w, r, http.StatusBadRequest, err)
				return
			}
			s.respondNewsletterError(w, r, action, err)
			return
		}

		s.respondJSON(w, r, map[string]interface{}{"Details": details})
	}
}

// newsletterBadRequest marks a validation error of the request body.
type newsletterBadRequest struct{ message string }

func (e newsletterBadRequest) Error() string { return e.message }

// FollowNewsletter makes the connected account follow a channel.
func (s *server) FollowNewsletter() http.HandlerFunc {
	return s.newsletterAction("follow newsletter", "Newsletter followed successfully",
		func(r *http.Request, client *whatsmeow.Client, jid types.JID, _ newsletterJIDStruct) error {
			return client.FollowNewsletter(r.Context(), jid)
		})
}

// UnfollowNewsletter makes the connected account stop following a channel.
func (s *server) UnfollowNewsletter() http.HandlerFunc {
	return s.newsletterAction("unfollow newsletter", "Newsletter unfollowed successfully",
		func(r *http.Request, client *whatsmeow.Client, jid types.JID, _ newsletterJIDStruct) error {
			return client.UnfollowNewsletter(r.Context(), jid)
		})
}

// MuteNewsletter mutes or unmutes the updates of a channel.
func (s *server) MuteNewsletter() http.HandlerFunc {
	return s.newsletterAction("mute newsletter", "Newsletter mute updated successfully",
		func(r *http.Request, client *whatsmeow.Client, jid types.JID, body newsletterJIDStruct) error {
			if body.Mute == nil {
				return newsletterBadRequest{"missing mute in Payload"}
			}
			return client.NewsletterToggleMute(r.Context(), jid, *body.Mute)
		})
}

// DeleteNewsletter permanently deletes a channel owned by the connected account.
func (s *server) DeleteNewsletter() http.HandlerFunc {
	return s.newsletterAction("delete newsletter", "Newsletter deleted successfully",
		func(r *http.Request, client *whatsmeow.Client, jid types.JID, _ newsletterJIDStruct) error {
			return client.DeleteNewsletter(r.Context(), jid)
		})
}

// reactToNewsletter sends or removes a reaction on a channel message. Channel
// messages are addressed by their server id, not by the message id.
func (s *server) reactToNewsletter(w http.ResponseWriter, r *http.Request, client *whatsmeow.Client, jid types.JID, serverID int, reaction, msgid string) {
	if serverID <= 0 {
		s.Respond(w, r, http.StatusBadRequest, errors.New("missing ServerID in Payload: channel messages are identified by their server id"))
		return
	}

	if err := client.NewsletterSendReaction(r.Context(), jid, serverID, reaction, ""); err != nil {
		s.respondNewsletterError(w, r, "react to newsletter message", err)
		return
	}

	s.respondJSON(w, r, map[string]interface{}{"Details": "Sent", "Id": msgid, "ServerID": serverID})
}
