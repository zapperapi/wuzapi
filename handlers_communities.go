package main

// Community handlers.
//
// A WhatsApp community is a parent group (IsParent) that holds linked groups.
// whatsmeow exposes the calls, but upstream wuzapi does not surface them:
//   POST /community/create            -> create a community
//   POST /community/group/create      -> create a group inside a community
//   POST /community/link              -> link an existing group to a community
//   POST /community/unlink            -> unlink a group from a community
//   GET  /community/groups            -> list the groups of a community
//   GET  /community/participants      -> list the participants of all the groups of a community
//
// Kept in a dedicated file to minimise rebase conflicts against upstream.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/types"
	"github.com/rs/zerolog/log"
)

// respondJSON marshals a value and sends it inside the usual envelope.
func (s *server) respondJSON(w http.ResponseWriter, r *http.Request, value interface{}) {
	responseJson, err := json.Marshal(value)
	if err != nil {
		s.Respond(w, r, http.StatusInternalServerError, err)
		return
	}
	s.Respond(w, r, http.StatusOK, string(responseJson))
}

// parseJIDList parses phone numbers or JIDs. ok is false on the first invalid value.
func parseJIDList(values []string) ([]types.JID, bool) {
	jids := make([]types.JID, len(values))
	for i, value := range values {
		jid, ok := parseJID(value)
		if !ok {
			return nil, false
		}
		jids[i] = jid
	}
	return jids, true
}

// CreateCommunity creates a community. WhatsApp creates the announcement group
// of the community automatically.
func (s *server) CreateCommunity() http.HandlerFunc {

	type createCommunityStruct struct {
		Name string `json:"name"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t createCommunityStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		if t.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Name in Payload"))
			return
		}

		req := whatsmeow.ReqCreateGroup{Name: t.Name}
		req.IsParent = true

		info, err := client.CreateGroup(r.Context(), req)
		if err != nil {
			msg := fmt.Sprintf("failed to create community: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
			return
		}

		s.respondJSON(w, r, info)
	}
}

// CreateCommunityGroup creates a group inside a community.
func (s *server) CreateCommunityGroup() http.HandlerFunc {

	type createCommunityGroupStruct struct {
		CommunityJID string   `json:"communityjid"`
		Name         string   `json:"name"`
		Participants []string `json:"participants"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t createCommunityGroupStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		community, ok := parseJID(t.CommunityJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Community JID"))
			return
		}

		if t.Name == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Name in Payload"))
			return
		}

		participants, ok := parseJIDList(t.Participants)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Participant Phone"))
			return
		}

		req := whatsmeow.ReqCreateGroup{Name: t.Name, Participants: participants}
		req.LinkedParentJID = community

		info, err := client.CreateGroup(r.Context(), req)
		if err != nil {
			msg := fmt.Sprintf("failed to create community group: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
			return
		}

		s.respondJSON(w, r, info)
	}
}

// communityLinkHandler links (link=true) or unlinks an existing group.
func (s *server) communityLinkHandler(link bool) http.HandlerFunc {

	type communityLinkStruct struct {
		CommunityJID string `json:"communityjid"`
		GroupJID     string `json:"groupjid"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		var t communityLinkStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}

		community, ok := parseJID(t.CommunityJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Community JID"))
			return
		}
		group, ok := parseJID(t.GroupJID)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Group JID"))
			return
		}

		var err error
		action := "link"
		if link {
			err = client.LinkGroup(r.Context(), community, group)
		} else {
			action = "unlink"
			err = client.UnlinkGroup(r.Context(), community, group)
		}
		if err != nil {
			msg := fmt.Sprintf("failed to %s community group: %v", action, err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
			return
		}

		s.respondJSON(w, r, map[string]interface{}{"Details": "Community group " + action + "ed successfully"})
	}
}

// LinkCommunityGroup links an existing group to a community.
func (s *server) LinkCommunityGroup() http.HandlerFunc { return s.communityLinkHandler(true) }

// UnlinkCommunityGroup removes a group from a community. The group continues to exist.
func (s *server) UnlinkCommunityGroup() http.HandlerFunc { return s.communityLinkHandler(false) }

// communityFromQuery reads and parses the communityJID query parameter.
func (s *server) communityFromQuery(w http.ResponseWriter, r *http.Request) (types.JID, bool) {
	value := r.URL.Query().Get("communityJID")
	if value == "" {
		s.Respond(w, r, http.StatusBadRequest, errors.New("missing communityJID parameter"))
		return types.EmptyJID, false
	}
	community, ok := parseJID(value)
	if !ok {
		s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Community JID"))
		return types.EmptyJID, false
	}
	return community, true
}

// GetCommunityGroups lists the groups of a community, the announcement group included.
// Each item keeps JID, Name and IsDefaultSubGroup, and adds IsGeneralChat, IsHidden,
// MembershipApprovalMode and HasMembershipRequest (filled only by the MEX query).
func (s *server) GetCommunityGroups() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		community, ok := s.communityFromQuery(w, r)
		if !ok {
			return
		}

		groups, err := client.GetCommunitySubGroups(r.Context(), community)
		if err != nil {
			msg := fmt.Sprintf("failed to get community groups: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
			return
		}

		// Wrapped in an object: an empty slice would marshal to null.
		s.respondJSON(w, r, map[string]interface{}{"Groups": groups})
	}
}

// GetCommunityParticipants lists the participants of all the groups of a community.
func (s *server) GetCommunityParticipants() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		community, ok := s.communityFromQuery(w, r)
		if !ok {
			return
		}

		participants, err := client.GetLinkedGroupsParticipants(r.Context(), community)
		if err != nil {
			msg := fmt.Sprintf("failed to get community participants: %v", err)
			log.Error().Msg(msg)
			s.Respond(w, r, http.StatusInternalServerError, errors.New(msg))
			return
		}

		s.respondJSON(w, r, map[string]interface{}{"Participants": participants})
	}
}
