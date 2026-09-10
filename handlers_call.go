package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"wuzapi/internal/meowcaller"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// Call handlers (feature 020). The contract is specs/020-chamadas-device/contracts/
// internal-apis.md; zapperapi-manager is the only caller, and it translates these
// status codes into the customer-facing error catalogue.
//
// Status codes carry meaning here and must not be collapsed into 500:
//
//	409  the instance is busy; the body names the call holding the seat
//	404  no such call for this instance
//	422  the target has no WhatsApp account, or the media cannot be played
//	500  no session, or the calling stack is unavailable

// maxCallAudioBytes caps what a single playback may download.
//
// The manager already enforces the platform's audio size limit before handing over a
// URL; this is the second line, so a bad or hostile URL cannot exhaust the instance
// server's disk.
const maxCallAudioBytes = 32 << 20 // 32 MiB

// callAudioDownloadTimeout bounds fetching the normalized WAV.
//
// SC-003 gives the whole playback path 3 seconds, and this fetch is inside it. A
// stalled URL must fail fast and leave the call up, never hold the request open.
const callAudioDownloadTimeout = 10 * time.Second

// resolveCallEngine returns the instance's calling stack, or an error naming why it
// is unavailable.
func (s *server) resolveCallEngine(userID string) (*callEngine, error) {
	if clientManager.GetWhatsmeowClient(userID) == nil {
		return nil, errors.New("no session")
	}
	mycli := clientManager.GetMyClient(userID)
	if mycli == nil || mycli.callEngine == nil {
		return nil, errors.New("calling stack unavailable for this instance")
	}
	return mycli.callEngine, nil
}

// respondCall writes the {"Details","Data"} envelope the other wuzapi routes use.
func (s *server) respondCall(w http.ResponseWriter, r *http.Request, details string, data map[string]interface{}) {
	body, err := json.Marshal(map[string]interface{}{"Details": details, "Data": data})
	if err != nil {
		s.Respond(w, r, http.StatusInternalServerError, err)
		return
	}
	s.Respond(w, r, http.StatusOK, string(body))
}

// respondCallBusy reports a seat conflict WITH the occupying call's ID.
//
// The ID is the whole point of the error: it is what lets the customer's automation
// end the right call instead of discovering it by trial and error (FR-024). A 409
// without it would be the opaque failure this feature exists to remove.
func (s *server) respondCallBusy(w http.ResponseWriter, r *http.Request, busyWith string) {
	s.Respond(w, r, http.StatusConflict, errors.New("call in progress: "+busyWith))
}

// StartCall places an outbound call (FR-005).
func (s *server) StartCall() http.HandlerFunc {
	type startCallStruct struct {
		Phone  string `json:"Phone"`
		Record bool   `json:"Record"`
		// AgentID identifica o atendente que conduz a chamada ao vivo (feature 021).
		// Vazio significa chamada automatizada por API, que é o caminho da 020 e continua
		// funcionando sem alteração (FR-003).
		AgentID string `json:"AgentID"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		engine, err := s.resolveCallEngine(txtid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		var t startCallStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}
		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Phone in Payload"))
			return
		}

		// Claim the seat BEFORE touching the network. Placing the offer first and
		// reserving afterwards would let two offers reach WhatsApp before either was
		// refused (FR-025).
		lc, busyWith, err := GetCallRegistry().claim(txtid, CallDirectionBusinessInitiated, t.Phone, t.Record)
		if err != nil {
			s.respondCallBusy(w, r, busyWith)
			return
		}

		call, err := engine.client.Call(context.Background(), t.Phone)
		if err != nil {
			// The offer never happened, so the seat must not stay held. Everything
			// that can fail here -- an unreachable peer, a number with no WhatsApp
			// account -- means the same thing to the customer: this recipient is not
			// callable (FR-007).
			GetCallRegistry().release(txtid)
			// The error is NOT logged: meowcaller embeds the dialed number in it
			// ("usync <number>: ..."), and a phone number in the clear is exactly
			// what FR-042 forbids in logs. The customer still receives the detail in
			// the response -- it is their own number, and they are not the leak.
			log.Warn().
				Str("instanceID", txtid).
				Msg("Outbound call could not be placed — target unreachable")
			s.Respond(w, r, http.StatusUnprocessableEntity, fmt.Errorf("invalid call target: %v", err))
			return
		}

		GetCallRegistry().bind(txtid, call.ID(), call)
		engine.watch(lc, call)

		// Chamada ao vivo: a voz do atendente passa a ser a fonte de áudio da chamada, e a
		// do contato passa a chegar ao navegador dele (feature 021).
		//
		// Falhar aqui **não** derruba a chamada que acabou de ser originada: o contato já
		// está tocando, e desistir agora produziria uma ligação fantasma no aparelho dele. O
		// atendente recebe a transição de estado normalmente e ouve silêncio, que é uma
		// falha diagnosticável — ao contrário de uma chamada que some sem explicação.
		if t.AgentID != "" {
			if err := attachAgentToCall(txtid, t.AgentID, lc); err != nil {
				log.Error().Err(err).
					Str("instanceID", txtid).
					Str("call_id", call.ID()).
					Msg("Softphone agent could not be attached to the call it started")
			}
		}

		log.Info().
			Str("instanceID", txtid).
			Str("call_id", call.ID()).
			Bool("record", t.Record).
			Bool("live", t.AgentID != "").
			Msg("Outbound call placed")

		s.respondCall(w, r, "Call started", map[string]interface{}{
			"CallID": call.ID(),
			"State":  string(CallStateRinging),
			"Peer":   call.Peer().String(),
		})
	}
}

// AnswerCall answers a ringing inbound call (FR-009).
func (s *server) AnswerCall() http.HandlerFunc {
	type answerCallStruct struct {
		CallID string `json:"CallID"`
		Record bool   `json:"Record"`
		// AgentID identifica o atendente que aceitou a chamada ao vivo (feature 021).
		// Vazio mantém o caminho automatizado da 020 (FR-003, FR-025).
		AgentID string `json:"AgentID"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		engine, err := s.resolveCallEngine(txtid)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		var t answerCallStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}
		if t.CallID == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing CallID in Payload"))
			return
		}

		// takePending removes on read: an offer is answerable once. A second attempt
		// must see "no longer available" rather than act on a dead handle (FR-011).
		call := engine.takePending(t.CallID)
		if call == nil {
			// Feature 021, US4-AS4: quem perde a corrida precisa saber que a chamada **já
			// foi atendida**, e não que ela nunca existiu. A diferença aparece na tela do
			// atendente — "atendida por outro" é situação normal numa operação com vários
			// atendentes; "não encontrada" faz a pessoa concluir que o sistema falhou.
			if incomingOfferOutcome(txtid, t.CallID) == incomingOfferTaken {
				s.Respond(w, r, http.StatusConflict, errors.New("call was already answered"))
				return
			}
			s.Respond(w, r, http.StatusNotFound, errors.New("call not found"))
			return
		}

		lc, busyWith, err := GetCallRegistry().adopt(txtid, t.CallID, call.Peer().String(), call, t.Record)
		if err != nil {
			s.respondCallBusy(w, r, busyWith)
			return
		}

		engine.watch(lc, call)

		if err := call.Answer(); err != nil {
			GetCallRegistry().releaseCall(txtid, t.CallID)
			log.Warn().
				Str("instanceID", txtid).
				Str("call_id", t.CallID).
				Err(err).
				Msg("Call could not be answered")
			s.Respond(w, r, http.StatusConflict, errors.New("call is no longer available"))
			return
		}

		// Os demais atendentes param de tocar. O motivo é ANSWERED_ELSEWHERE, e não um
		// erro: para eles, a chamada teve o desfecho normal de ter sido atendida (FR-023,
		// FR-024, US4-AS3).
		publishIncomingCleared(txtid, t.CallID, incomingClearedAnswered)

		// Chamada ao vivo: a voz do atendente vira a fonte de áudio, e a do contato passa a
		// chegar ao navegador dele. Falhar aqui não desfaz o atendimento — a ligação já está
		// estabelecida, e derrubá-la agora seria pior do que um silêncio diagnosticável.
		if t.AgentID != "" {
			if err := attachAgentToCall(txtid, t.AgentID, lc); err != nil {
				log.Error().Err(err).
					Str("instanceID", txtid).
					Str("call_id", t.CallID).
					Msg("Softphone agent could not be attached to the call it answered")
			}
		}

		log.Info().
			Str("instanceID", txtid).
			Str("call_id", t.CallID).
			Bool("record", t.Record).
			Bool("live", t.AgentID != "").
			Msg("Call answered")

		// Peer travels back so the platform's record is born with the real contact
		// instead of waiting for the first state event to fill it in.
		s.respondCall(w, r, "Call answered", map[string]interface{}{
			"CallID": t.CallID,
			"State":  string(CallStateActive),
			"Peer":   lc.Peer,
		})
	}
}

// HangupCall ends the active call by command (FR-019).
func (s *server) HangupCall() http.HandlerFunc {
	type hangupCallStruct struct {
		CallID string `json:"CallID"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if _, err := s.resolveCallEngine(txtid); err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		var t hangupCallStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}
		if t.CallID == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing CallID in Payload"))
			return
		}

		lc, err := GetCallRegistry().get(txtid, t.CallID)
		if err != nil {
			s.Respond(w, r, http.StatusNotFound, errors.New("call not found"))
			return
		}
		if lc.call == nil {
			s.Respond(w, r, http.StatusConflict, errors.New("call is no longer available"))
			return
		}

		// Stop any playback first: hanging up mid-audio must not leave a Player
		// writing into a call that no longer exists (FR-019, US3-AS2).
		lc.stopPlayback()

		if err := lc.call.Hangup(); err != nil {
			log.Warn().
				Str("instanceID", txtid).
				Str("call_id", t.CallID).
				Err(err).
				Msg("Hangup failed")
			s.Respond(w, r, http.StatusConflict, errors.New("call is no longer available"))
			return
		}

		log.Info().Str("instanceID", txtid).Str("call_id", t.CallID).Msg("Call ended by command")

		s.respondCall(w, r, "Call ended", map[string]interface{}{
			"CallID":  t.CallID,
			"Outcome": string(CallOutcomeTerminatedByBusiness),
		})
	}
}

// PlayCallAudio plays an audio file into an active call (FR-013).
//
// The URL points at a WAV the manager already normalized to 16 kHz mono through
// media-processor. This server never converts audio -- that boundary belongs to
// media-processor alone (Princípio I).
func (s *server) PlayCallAudio() http.HandlerFunc {
	type playAudioStruct struct {
		CallID   string `json:"CallID"`
		AudioURL string `json:"AudioURL"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		if _, err := s.resolveCallEngine(txtid); err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
			return
		}

		var t playAudioStruct
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}
		if t.CallID == "" || t.AudioURL == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing CallID or AudioURL in Payload"))
			return
		}

		lc, err := GetCallRegistry().get(txtid, t.CallID)
		if err != nil {
			s.Respond(w, r, http.StatusNotFound, errors.New("call not found"))
			return
		}
		if lc.State() != CallStateActive {
			// Still ringing: there is nobody on the line to hear it. The call keeps
			// ringing -- this is a refusal, not a teardown (FR-016).
			s.Respond(w, r, http.StatusConflict, errors.New("call is not established yet"))
			return
		}

		path, err := downloadCallAudio(t.AudioURL)
		if err != nil {
			// Media failure NEVER ends the call. The customer fixes the URL and tries
			// again with the contact still on the line (FR-015, US7).
			// The error is NOT logged: Go wraps the full URL into transport errors,
			// and the media URL is a signed link. A secret in a log is a secret
			// leaked (Princípio VI).
			log.Warn().
				Str("instanceID", txtid).
				Str("call_id", t.CallID).
				Msg("Call audio could not be fetched — call stays active")
			s.Respond(w, r, http.StatusUnprocessableEntity, fmt.Errorf("invalid call media: %v", err))
			return
		}
		// The file outlives this request: meowcaller streams from it while the call
		// plays. Its lifetime belongs to the playback, not to the handler.
		cleanup := func() { os.Remove(path) }

		source, err := meowcaller.WAVFile(path)
		if err != nil {
			cleanup()
			log.Warn().
				Str("instanceID", txtid).
				Str("call_id", t.CallID).
				Err(err).
				Msg("Call audio is not playable — call stays active")
			s.Respond(w, r, http.StatusUnprocessableEntity, fmt.Errorf("invalid call media: %v", err))
			return
		}

		// A new request replaces whatever is playing: a call never carries two
		// overlapping audios (FR-018).
		startedAt, err := lc.play(source, cleanup)
		if err != nil {
			s.Respond(w, r, http.StatusConflict, errors.New("call is no longer available"))
			return
		}

		log.Info().
			Str("instanceID", txtid).
			Str("call_id", t.CallID).
			Msg("Call audio playback started")

		s.respondCall(w, r, "Playback started", map[string]interface{}{
			"CallID":    t.CallID,
			"StartedAt": startedAt.UTC().Format(time.RFC3339),
		})
	}
}

// downloadCallAudio fetches the normalized WAV to a temporary file.
//
// Bounded on both axes -- time and size -- because the URL is chosen by the caller
// and this runs inside a request the customer is waiting on.
func downloadCallAudio(url string) (string, error) {
	client := &http.Client{Timeout: callAudioDownloadTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("media is unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("media is unreachable: status %d", resp.StatusCode)
	}

	file, err := os.CreateTemp("", "call-audio-*.wav")
	if err != nil {
		return "", err
	}
	written, err := io.Copy(file, io.LimitReader(resp.Body, maxCallAudioBytes+1))
	closeErr := file.Close()
	if err != nil {
		os.Remove(file.Name())
		return "", fmt.Errorf("media could not be read: %w", err)
	}
	if closeErr != nil {
		os.Remove(file.Name())
		return "", closeErr
	}
	if written > maxCallAudioBytes {
		os.Remove(file.Name())
		return "", fmt.Errorf("media exceeds the %d byte limit", int64(maxCallAudioBytes))
	}
	return file.Name(), nil
}

// ServeRecordingTrack streams one captured track to media-processor.
//
// Deliberately OUTSIDE the token middleware: media-processor fetches it with a
// plain GET, and threading the instance token through a service that has no
// business knowing it would be worse than the alternative. The path itself is the
// credential -- 32 bytes from crypto/rand, valid for an hour, and mapped to nothing
// but one file (see recordingStore).
//
// Unknown or expired token is a flat 404: there is nothing here to enumerate.
func (s *server) ServeRecordingTrack() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSuffix(mux.Vars(r)["token"], ".wav")

		path, ok := GetRecordingStore().resolve(token)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		file, err := os.Open(path)
		if err != nil {
			log.Warn().Err(err).Msg("Recording track could not be opened")
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "audio/wav")
		// ServeContent handles range requests and the Content-Length, which is what
		// lets the fetcher stream a long recording instead of buffering it whole.
		http.ServeContent(w, r, "track.wav", info.ModTime(), file)
	}
}
