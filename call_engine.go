package main

import (
	"strings"
	"sync"
	"time"

	"wuzapi/internal/meowcaller"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/rs/zerolog/log"
)

// CallOutcome mirrors the CallOutcome enum persisted by zapperapi-manager, so a value
// crosses the wire without translation (FR-033).
type CallOutcome string

const (
	CallOutcomeCompleted            CallOutcome = "COMPLETED"
	CallOutcomeRejected             CallOutcome = "REJECTED"
	CallOutcomeMissed               CallOutcome = "MISSED"
	CallOutcomeUnavailable          CallOutcome = "UNAVAILABLE"
	CallOutcomeTerminatedByBusiness CallOutcome = "TERMINATED_BY_BUSINESS"
	CallOutcomeFailed               CallOutcome = "FAILED"
)

// callOutcomeByReason translates meowcaller's OnEnd reason into a published outcome.
//
// A data table, not a chain of conditionals: a reason observed in production becomes
// a line here, never a branch. An unmapped reason deliberately yields no outcome --
// the reason still reaches the customer verbatim, and the gap is logged so this table
// grows from what production actually emits, not from guesses.
//
// Two vocabularies land in the same map, which is why it is one map:
//
//   - WhatsApp's own CallTerminate.Reason (reject, timeout, bye, ...), which the
//     platform already mapped for the observation-only path in feature 018.
//   - meowcaller's local reasons ("hangup", "rejected"), emitted when this server is
//     the one ending the call. These carry information the protocol reason cannot:
//     "the business hung up" is not something the peer tells us.
var callOutcomeByReason = map[string]CallOutcome{
	// Ended by us, through the API.
	"hangup":   CallOutcomeTerminatedByBusiness,
	"rejected": CallOutcomeRejected,

	// Ended by the peer or the network.
	"reject":           CallOutcomeRejected,
	"decline":          CallOutcomeRejected,
	"timeout":          CallOutcomeMissed,
	"busy":             CallOutcomeUnavailable,
	"bye":              CallOutcomeCompleted,
	"accept_elsewhere": CallOutcomeCompleted,
	"connection-error": CallOutcomeFailed,

	// Feature 021: o atendente não voltou dentro do período de graça (FR-039). Motivo
	// próprio para o log distinguir "a ligação falhou" de "o atendente sumiu"; o desfecho
	// publicado ao cliente é o mesmo `FAILED` nos dois casos.
	callEndReasonAgentLost: CallOutcomeFailed,
}

// resolveCallOutcome maps an OnEnd reason to an outcome, or reports that the table
// does not cover it.
//
// Every "server:<code>" reason is a signaling failure regardless of the code, so it
// is matched by prefix rather than enumerated -- a code we have never seen still
// classifies correctly.
func resolveCallOutcome(reason string) (CallOutcome, bool) {
	if reason == "" {
		return "", false
	}
	if strings.HasPrefix(reason, "server:") {
		return CallOutcomeFailed, true
	}
	outcome, ok := callOutcomeByReason[reason]
	return outcome, ok
}

// callEngine drives one instance's calls on top of meowcaller.
//
// It owns nothing about concurrency: the seat is the callRegistry's business
// (research §R3). What lives here is the lifecycle -- wiring meowcaller's listeners
// to the platform's events, and making sure every exit path releases the seat.
type callEngine struct {
	instanceID string
	client     *meowcaller.Client

	// emit publishes a call event to the customer's webhook. Injected so the engine
	// stays testable without a live client.
	emit func(map[string]interface{})

	mu sync.Mutex
	// pending holds inbound offers that have arrived but were neither answered nor
	// rejected yet. They do not occupy the instance's seat.
	pending map[string]*meowcaller.Call
}

// newCallEngine wires meowcaller for one instance.
//
// WithTypedCallAcks(false) is the fork's patch 3: this build lets hypermeow keep
// dispatching <call> nodes, so hypermeow is also the one that acks them. Acking here
// too would answer the peer twice (see internal/meowcaller/UPSTREAM.md).
//
// Must run BEFORE the whatsmeow client connects -- meowcaller refuses to install its
// node interception on a client whose receive loop is already running.
func newCallEngine(instanceID string, wa *whatsmeow.Client, emit func(map[string]interface{})) *callEngine {
	e := &callEngine{instanceID: instanceID, emit: emit, pending: make(map[string]*meowcaller.Call)}
	e.client = meowcaller.NewClient(
		wa,
		meowcaller.WithLogger(log.With().Str("instanceID", instanceID).Logger()),
		meowcaller.WithTypedCallAcks(false),
	)
	e.client.OnIncomingCall(e.onIncomingCall)
	return e
}

// onIncomingCall records an offer so the API can answer or reject it by ID.
//
// It does NOT claim the instance's seat: an inbound call that nobody answers must not
// block outbound calls. The seat is claimed at answer time (FR-023 counts a call the
// platform is conducting, and an unanswered offer is not one).
//
// The customer already learns about the offer through the CallOffer stanza that
// hypermeow keeps dispatching, so nothing is published here.
func (e *callEngine) onIncomingCall(call *meowcaller.Call) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending == nil {
		e.pending = make(map[string]*meowcaller.Call)
	}
	e.pending[call.ID()] = call

	log.Info().
		Str("instanceID", e.instanceID).
		Str("call_id", call.ID()).
		Msg("Incoming call offer registered")

	// Feature 021: a oferta toca em todos os atendentes conectados desta instância. Sem
	// nenhum conectado, isto é um laço sobre um mapa vazio, e o caminho da 020 segue
	// exatamente como está (FR-021, FR-025).
	publishIncomingCall(e.instanceID, call.ID(), call.Peer().String())

	call.OnEnd(func(reason string) {
		e.mu.Lock()
		_, wasPending := e.pending[call.ID()]
		delete(e.pending, call.ID())
		e.mu.Unlock()

		// Uma oferta que morre AINDA pendente é o contato desistindo antes de qualquer
		// aceite: os componentes precisam parar de tocar (FR-024, US4-AS6). Se ela já não
		// estava pendente, alguém a tomou, e quem cessa a sinalização é quem a tomou —
		// com o motivo correto, que aqui não temos como saber.
		if wasPending {
			publishIncomingCleared(e.instanceID, call.ID(), incomingClearedAbandoned)
		}

		// Only report calls the platform actually took: an unanswered offer that
		// expires is already described by the CallTerminate stanza, and publishing a
		// second event for it would duplicate what feature 018 delivers.
		if lc, err := GetCallRegistry().get(e.instanceID, call.ID()); err == nil {
			e.finish(lc, reason)
		}
	})
}

// takePending removes and returns a registered inbound offer.
//
// Removing on read is deliberate: an offer is answerable or rejectable once, and a
// second attempt must see "no longer available" rather than act on a dead handle
// (FR-011).
func (e *callEngine) takePending(callID string) *meowcaller.Call {
	e.mu.Lock()
	defer e.mu.Unlock()
	call := e.pending[callID]
	delete(e.pending, callID)
	return call
}

// watch attaches the lifecycle listeners that turn a meowcaller call into platform
// events and keep the seat honest.
func (e *callEngine) watch(lc *liveCall, call *meowcaller.Call) {
	call.OnPeerAccept(func() { e.established(lc) })
	call.OnStateChange(func(phase meowcaller.CallPhase) {
		// Answering an inbound call never fires OnPeerAccept -- the peer accepted
		// nothing, we did. CallPhaseActive is the transition that covers both
		// directions.
		if phase == meowcaller.CallPhaseActive {
			e.established(lc)
		}
	})
	call.OnEnd(func(reason string) { e.finish(lc, reason) })
}

// established publishes the call becoming active, exactly once.
func (e *callEngine) established(lc *liveCall) {
	lc.mu.Lock()
	if lc.state != CallStateRinging {
		lc.mu.Unlock()
		return // already active, or already over
	}
	lc.state = CallStateActive
	lc.EstablishedAt = time.Now()
	call, wantsRecording := lc.call, lc.Recording
	lc.mu.Unlock()

	// Recording starts at establishment, never at the offer: a phone that is only
	// ringing carries no conversation to capture (FR-029).
	if wantsRecording && call != nil {
		e.startRecording(lc, call)
	}

	log.Info().
		Str("instanceID", e.instanceID).
		Str("call_id", lc.CallID).
		Msg("Call established")

	e.publish(lc, CallStateActive, "", "")
}

// finish releases the seat and publishes the outcome, exactly once.
//
// Releasing before publishing is deliberate: if the webhook path is slow or broken,
// the instance must already be free to take the next call (FR-020, SC-006).
func (e *callEngine) finish(lc *liveCall, reason string) {
	lc.mu.Lock()
	if lc.state == CallStateEnded {
		lc.mu.Unlock()
		return // already reported; the outcome is published exactly once
	}
	lc.state = CallStateEnded
	// Under the same lock as the state change: a playback must never keep streaming
	// into a call that is over, nor leave its temporary file behind.
	lc.stopPlaybackLocked()
	lc.mu.Unlock()

	GetCallRegistry().releaseCall(e.instanceID, lc.CallID)

	outcome, mapped := resolveCallOutcome(reason)
	if !mapped {
		// The customer still gets the raw reason; this log is what grows the table.
		// "reason" is protocol vocabulary, never contact data (FR-042).
		log.Warn().
			Str("instanceID", e.instanceID).
			Str("call_id", lc.CallID).
			Str("reason", reason).
			Msg("Unmapped call end reason — event carries no outcome")
	}

	log.Info().
		Str("instanceID", e.instanceID).
		Str("call_id", lc.CallID).
		Str("outcome", string(outcome)).
		Msg("Call ended")

	// The terminate event goes out FIRST and does not wait for the recording: the
	// customer learns the outcome immediately, and the recording arrives in its own
	// event when it is ready (FR-034, US4-AS4).
	e.publish(lc, CallStateEnded, outcome, reason)
	e.finishRecording(lc)
}

// startRecording attaches the two-leg capture to a call that asked for it.
//
// A failure here is NOT a call failure: the conversation goes on, and the customer
// learns the recording is unavailable through its own event (FR-036). Losing the call
// because a file could not be opened would be the worse trade by far.
func (e *callEngine) startRecording(lc *liveCall, call *meowcaller.Call) {
	recorder, err := newCallRecorder(e.instanceID, lc.CallID)
	if err != nil {
		log.Warn().
			Str("instanceID", e.instanceID).
			Str("call_id", lc.CallID).
			Err(err).
			Msg("Recording could not be started — call continues without it")
		e.emitRecordingFailed(lc.CallID, "STORAGE_FAILED")
		return
	}

	lc.mu.Lock()
	lc.recorder = recorder
	lc.mu.Unlock()

	call.Receive(recorder.Sink())

	log.Info().
		Str("instanceID", e.instanceID).
		Str("call_id", lc.CallID).
		Msg("Recording started")
}

// finishRecording closes the capture and reports it, once.
func (e *callEngine) finishRecording(lc *liveCall) {
	lc.mu.Lock()
	recorder := lc.recorder
	lc.recorder = nil
	lc.mu.Unlock()
	if recorder == nil {
		return
	}

	result := recorder.Close()

	// Nothing captured: the call ended before any audio flowed. Delivering an empty
	// file would be worse than saying so.
	if result.DurationSeconds == 0 {
		recorder.Discard()
		e.emitRecordingFailed(lc.CallID, "STORAGE_FAILED")
		return
	}

	log.Info().
		Str("instanceID", e.instanceID).
		Str("call_id", lc.CallID).
		Int("duration_seconds", result.DurationSeconds).
		Bool("truncated", result.Truncated).
		Msg("Recording finished")

	// Tokens, not paths: the platform builds fetchable URLs from them and hands
	// those to media-processor, which mixes the two legs (research §R4).
	remoteToken, localToken, err := publishRecordingTracks(result)
	if err != nil {
		log.Warn().
			Str("instanceID", e.instanceID).
			Str("call_id", lc.CallID).
			Err(err).
			Msg("Recording tracks could not be published")
		recorder.Discard()
		e.emitRecordingFailed(lc.CallID, "STORAGE_FAILED")
		return
	}

	if e.emit == nil {
		return
	}
	e.emit(map[string]interface{}{
		"type": "CallRecordingReady",
		"event": map[string]interface{}{
			"CallID":           lc.CallID,
			"RemoteTrackToken": remoteToken,
			"LocalTrackToken":  localToken,
			"DurationSeconds":  result.DurationSeconds,
			"Truncated":        result.Truncated,
			"Timestamp":        time.Now().UTC().Format(time.RFC3339),
		},
	})
}

func (e *callEngine) emitRecordingFailed(callID, reason string) {
	if e.emit == nil {
		return
	}
	e.emit(map[string]interface{}{
		"type": "CallRecordingFailed",
		"event": map[string]interface{}{
			"CallID":    callID,
			"Reason":    reason,
			"Timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// publish emits one CallStateChanged event.
//
// Never carries a phone number in the clear or any audio: the peer travels as the JID
// the platform already uses everywhere else, and the payload is state, not content
// (FR-042, FR-043).
func (e *callEngine) publish(lc *liveCall, state CallState, outcome CallOutcome, reason string) {
	if e.emit == nil {
		return
	}
	// Same envelope every other wuzapi webhook uses: the discriminator at the top,
	// the occurrence under "event". The platform reads body.event.X for every event
	// type, and a flat payload here would be the one exception nobody expects.
	event := map[string]interface{}{
		"CallID":    lc.CallID,
		"State":     string(state),
		"Direction": string(lc.Direction),
		"Peer":      lc.Peer,
		"Timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	if outcome != "" {
		event["Outcome"] = string(outcome)
	}
	if reason != "" {
		event["Reason"] = reason
	}

	// Feature 021: autoria da chamada, quando ela é conduzida ao vivo (FR-053, FR-055).
	//
	// Campo adicional em objeto existente — um leitor antigo o ignora, e SC-015 continua
	// valendo. Serve principalmente à chamada **entrante**: ali o `manager` não sabe quem
	// venceu a corrida até o servidor de instância dizer.
	if session := softphoneSessionConducting(e.instanceID, lc.CallID); session != nil {
		agent := session.Agent()
		event["AgentID"] = agent.ID
		if agent.DisplayName != "" {
			event["AgentDisplayName"] = agent.DisplayName
		}
	}

	e.emit(map[string]interface{}{
		"type":  "CallStateChanged",
		"event": event,
	})

	// Feature 021: a mesma transição vai, em um salto, às sessões de softphone abertas nesta
	// instância. O webhook continua sendo o caminho do cliente (FR-003); este é o caminho do
	// atendente, e existe porque SC-005 pede o estado no componente em 1 segundo — algo que
	// a fila do webhook não entrega e nem deveria.
	e.publishToAgents(lc, state, outcome, reason)
}

// publishToAgents entrega a transição às sessões de softphone da instância (FR-013, FR-014).
func (e *callEngine) publishToAgents(lc *liveCall, state CallState, outcome CallOutcome, reason string) {
	registry := GetSoftphoneRegistry()
	if len(registry.sessions(e.instanceID)) == 0 {
		return
	}

	data := map[string]any{
		"callId":    lc.CallID,
		"state":     softphoneCallState(state),
		"direction": string(lc.Direction),
		"contact":   map[string]any{"jid": lc.Peer},
		"at":        time.Now().UTC().Format(time.RFC3339),
	}
	if state == CallStateEnded {
		data["endedReason"] = softphoneEndedReason(outcome)
	}
	if lc.Recording {
		data["recording"] = map[string]any{"requested": true, "granted": true}
	}

	registry.broadcast(e.instanceID, map[string]any{"t": "call.state", "d": data})

	// Chamada encerrada libera a sessão para a próxima e publica a linha livre.
	if state == CallStateEnded {
		detachAgentFromCall(e.instanceID, lc.CallID)
		registry.broadcast(e.instanceID, map[string]any{
			"t": "line.update",
			"d": lineStatePayload(e.instanceID),
		})
	}
	_ = reason
}

// softphoneCallState traduz o estado persistido para o vocabulário da sessão.
//
// São vocabulários distintos de propósito: o registro e o webhook falam RINGING/ACTIVE/ENDED,
// que é o que a 020 publica e não pode mudar (SC-015); a sessão precisa de DIALING e
// RECONNECTING, que descrevem o que o atendente vê e não existem no registro.
func softphoneCallState(state CallState) string {
	switch state {
	case CallStateRinging:
		return "RINGING"
	case CallStateActive:
		return "ACTIVE"
	case CallStateEnded:
		return "ENDED"
	}
	return "IDLE"
}

// softphoneEndedReason traduz o desfecho persistido nos seis motivos que FR-014 exige
// distinguir. Nenhum desfecho novo é criado: é a mesma informação, na linguagem da sessão.
func softphoneEndedReason(outcome CallOutcome) string {
	switch outcome {
	case CallOutcomeTerminatedByBusiness:
		return "BY_AGENT"
	case CallOutcomeCompleted:
		return "BY_CONTACT"
	case CallOutcomeRejected:
		return "REJECTED"
	case CallOutcomeMissed:
		return "MISSED"
	case CallOutcomeUnavailable:
		return "UNAVAILABLE"
	}
	return "FAILED"
}

// dropInstanceCall ends whatever call an instance is on, with a FAILED outcome.
//
// The exits it covers -- lost WhatsApp session, server restart -- are not the call
// ending, they are the platform losing the ability to observe it. Neither leaves an
// instance pinned to a ghost call (FR-022, SC-006).
func (e *callEngine) dropInstanceCall(reason string) {
	// Offers that never became calls die with the session too: without this, a
	// disconnect that skips the terminate stanza would leave them registered for the
	// life of the process.
	e.mu.Lock()
	e.pending = make(map[string]*meowcaller.Call)
	e.mu.Unlock()

	lc := GetCallRegistry().drainInstance(e.instanceID)
	if lc == nil {
		return
	}
	log.Warn().
		Str("instanceID", e.instanceID).
		Str("call_id", lc.CallID).
		Str("reason", reason).
		Msg("Call dropped — instance released")
	e.publish(lc, CallStateEnded, CallOutcomeFailed, reason)
	// A dropped call still delivers whatever was captured: an abrupt ending is
	// exactly when the partial recording matters most (FR-029).
	e.finishRecording(lc)
}

// close tears down the node interception so a reconnect does not leak a goroutine.
func (e *callEngine) close() {
	if e.client != nil {
		e.client.Close()
	}
}
