package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// Rotas internas da ligação da Cloud API pelo softphone (feature 028, US6). O contrato é
// specs/028-operacao-e-ligacoes-cloud-api/contracts/internal-apis.md; o manager é o único
// chamador, com a autenticação administrativa.
//
// O manager conversa com a Meta; este servidor só cria e mantém a perna de mídia. O SDP
// atravessa estas rotas e nunca entra em log.
//
// Erros, com `code` no corpo para o manager traduzir:
//
//	409 AGENT_IN_CALL             o atendente já conduz uma ligação
//	409 NO_AGENT_SESSION          o atendente não tem sessão de softphone aberta
//	409 CALL_TAKEN                a ligação recebida já foi atendida por outro atendente
//	429 CONCURRENCY_LIMIT         a instância atingiu o teto de ligações simultâneas
//	502 MEDIA_NEGOTIATION_FAILED  a negociação de mídia com a Meta falhou
//	404 CALL_NOT_FOUND            nenhuma ligação com esse identificador nesta instância

// cloudCallBodyLimit limita o corpo: o SDP é o maior campo legítimo e fica bem abaixo disso.
const cloudCallBodyLimit = 256 * 1024

type cloudCallError struct {
	status int
	code   string
}

// cloudCallErrorFor traduz o erro do motor para o status e o código do contrato.
func cloudCallErrorFor(err error) cloudCallError {
	switch {
	case errors.Is(err, errCloudAgentInCall):
		return cloudCallError{http.StatusConflict, "AGENT_IN_CALL"}
	case errors.Is(err, errCloudNoAgentSession):
		return cloudCallError{http.StatusConflict, "NO_AGENT_SESSION"}
	case errors.Is(err, errCloudCallTaken):
		return cloudCallError{http.StatusConflict, "CALL_TAKEN"}
	case errors.Is(err, errCloudCallLimit):
		return cloudCallError{http.StatusTooManyRequests, "CONCURRENCY_LIMIT"}
	case errors.Is(err, errCloudCallNotFound):
		return cloudCallError{http.StatusNotFound, "CALL_NOT_FOUND"}
	}
	return cloudCallError{http.StatusBadGateway, "MEDIA_NEGOTIATION_FAILED"}
}

func writeCloudCallJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func writeCloudCallError(w http.ResponseWriter, err error) {
	mapped := cloudCallErrorFor(err)
	writeCloudCallJSON(w, mapped.status, map[string]any{
		"code":    mapped.code,
		"error":   err.Error(),
		"success": false,
	})
}

func writeCloudCallBadRequest(w http.ResponseWriter, message string) {
	writeCloudCallJSON(w, http.StatusBadRequest, map[string]any{
		"code":    "BAD_REQUEST",
		"error":   message,
		"success": false,
	})
}

// decodeCloudCallBody lê o corpo e exige `instanceId`.
func decodeCloudCallBody(w http.ResponseWriter, r *http.Request, target any, instanceID func() string) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, cloudCallBodyLimit)).Decode(target); err != nil {
		writeCloudCallBadRequest(w, "could not decode payload")
		return false
	}
	if strings.TrimSpace(instanceID()) == "" {
		writeCloudCallBadRequest(w, "instanceId is required")
		return false
	}
	return true
}

// CloudCallIncoming sinaliza a ligação recebida aos atendentes livres.
func (s *server) CloudCallIncoming() http.HandlerFunc {
	type body struct {
		InstanceID string       `json:"instanceId"`
		CallID     string       `json:"callId"`
		Contact    cloudContact `json:"contact"`
		At         string       `json:"at"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var b body
		if !decodeCloudCallBody(w, r, &b, func() string { return b.InstanceID }) {
			return
		}
		if b.CallID == "" {
			writeCloudCallBadRequest(w, "callId is required")
			return
		}
		at, err := time.Parse(time.RFC3339, b.At)
		if err != nil {
			at = time.Now()
		}
		publishCloudIncoming(b.InstanceID, b.CallID, b.Contact, at)
		w.WriteHeader(http.StatusNoContent)
	}
}

// CloudCallCleared faz os componentes pararem de sinalizar a ligação recebida.
func (s *server) CloudCallCleared() http.HandlerFunc {
	type body struct {
		InstanceID string `json:"instanceId"`
		Reason     string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var b body
		if !decodeCloudCallBody(w, r, &b, func() string { return b.InstanceID }) {
			return
		}
		reason := b.Reason
		if reason == "" {
			reason = incomingClearedAbandoned
		}
		publishIncomingCleared(b.InstanceID, mux.Vars(r)["callId"], reason)
		w.WriteHeader(http.StatusNoContent)
	}
}

// CloudCallOffer reserva a vaga do atendente e devolve a oferta SDP para a Meta.
func (s *server) CloudCallOffer() http.HandlerFunc {
	type body struct {
		InstanceID string       `json:"instanceId"`
		AgentID    string       `json:"agentId"`
		Contact    cloudContact `json:"contact"`
		Record     bool         `json:"record"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var b body
		if !decodeCloudCallBody(w, r, &b, func() string { return b.InstanceID }) {
			return
		}
		if b.AgentID == "" {
			writeCloudCallBadRequest(w, "agentId is required")
			return
		}
		call, sdp, err := s.cloudEngine().offer(b.InstanceID, b.AgentID, b.Contact, b.Record)
		if err != nil {
			log.Warn().Err(err).Str("instanceID", b.InstanceID).Str("agentID", b.AgentID).
				Msg("Cloud call offer refused")
			writeCloudCallError(w, err)
			return
		}
		writeCloudCallJSON(w, http.StatusOK, map[string]any{"legId": call.LegID, "sdp": sdp})
	}
}

// CloudCallRemoteAnswer aplica a resposta SDP da Meta à perna da ligação feita.
func (s *server) CloudCallRemoteAnswer() http.HandlerFunc {
	type body struct {
		InstanceID string `json:"instanceId"`
		CallID     string `json:"callId"`
		SDP        string `json:"sdp"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var b body
		if !decodeCloudCallBody(w, r, &b, func() string { return b.InstanceID }) {
			return
		}
		if b.SDP == "" {
			writeCloudCallBadRequest(w, "sdp is required")
			return
		}
		if err := s.cloudEngine().remoteAnswer(b.InstanceID, mux.Vars(r)["legId"], b.CallID, b.SDP); err != nil {
			writeCloudCallError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// CloudCallAccept produz a resposta SDP para a oferta da Meta.
func (s *server) CloudCallAccept() http.HandlerFunc {
	type body struct {
		InstanceID string       `json:"instanceId"`
		AgentID    string       `json:"agentId"`
		SDP        string       `json:"sdp"`
		Record     bool         `json:"record"`
		Contact    cloudContact `json:"contact"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var b body
		if !decodeCloudCallBody(w, r, &b, func() string { return b.InstanceID }) {
			return
		}
		if b.AgentID == "" || b.SDP == "" {
			writeCloudCallBadRequest(w, "agentId and sdp are required")
			return
		}
		callID := mux.Vars(r)["callId"]
		_, sdp, err := s.cloudEngine().accept(b.InstanceID, callID, b.AgentID, b.SDP, b.Contact, b.Record)
		if err != nil {
			log.Warn().Err(err).Str("instanceID", b.InstanceID).Str("call_id", callID).
				Msg("Cloud call accept refused")
			writeCloudCallError(w, err)
			return
		}
		writeCloudCallJSON(w, http.StatusOK, map[string]any{"sdp": sdp})
	}
}

// CloudCallEstablished libera o envio de mídia depois de a Meta confirmar o atendimento.
func (s *server) CloudCallEstablished() http.HandlerFunc {
	type body struct {
		InstanceID string `json:"instanceId"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var b body
		if !decodeCloudCallBody(w, r, &b, func() string { return b.InstanceID }) {
			return
		}
		if err := s.cloudEngine().established(b.InstanceID, mux.Vars(r)["callId"]); err != nil {
			writeCloudCallError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// CloudCallEnd fecha a perna e libera o atendente. Idempotente.
func (s *server) CloudCallEnd() http.HandlerFunc {
	type body struct {
		InstanceID string `json:"instanceId"`
		Reason     string `json:"reason"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var b body
		if !decodeCloudCallBody(w, r, &b, func() string { return b.InstanceID }) {
			return
		}
		s.cloudEngine().end(b.InstanceID, mux.Vars(r)["callId"], b.Reason)
		w.WriteHeader(http.StatusNoContent)
	}
}
