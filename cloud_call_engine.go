package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/rs/zerolog/log"

	"wuzapi/internal/meowcaller"
)

// Motor de ligação da Cloud API para o softphone (feature 028, US6, research R17).
//
// O manager conversa com a Meta (Graph API) e pede a este servidor a perna de mídia: uma
// `PeerConnection` voltada para a Meta, ligada à ponte de áudio da sessão do atendente. A
// prova de mídia (T100, `cmd/cloud-call-probe`) fixou as condições que a Meta aceita: este
// lado é ICE-full e cliente DTLS, a Meta é ICE-lite com IP público, Opus a 48 kHz, sem STUN.
//
// **Divergência declarada da research R17**: a pesquisa previa repassar os pacotes Opus entre
// as duas pernas sem decodificar. A implementação decodifica e recodifica em 16 kHz, pela
// mesma ponte de áudio do `device` (`liveAudioBridge`). Com isso o mudo no servidor (FR-027),
// o período de graça (FR-037), a reconexão (FR-038) e o tee da gravação (FR-030) funcionam
// exatamente como no `device`, sem um segundo caminho para cada um. O custo é a banda de voz
// de 16 kHz, a mesma das ligações do `device`.

const (
	// cloudFrameSamples é o quadro enviado à Meta: 20 ms a 16 kHz. A prova de mídia enviou
	// quadros de 20 ms, e é o que a Meta recebeu sem queda.
	cloudFrameSamples  = meowcaller.SampleRate / 50
	cloudFrameDuration = 20 * time.Millisecond
	// cloudOpusClockRate é o relógio RTP do Opus, fixo pela especificação.
	cloudOpusClockRate = 48000
)

// cloudGatherTimeout limita a coleta de candidatos. A Meta não aceita candidato depois do SDP,
// então a resposta só sai com a coleta completa ou com este prazo vencido.
var cloudGatherTimeout = 5 * time.Second

// errCloudNoAgentSession: o atendente não tem sessão de softphone aberta nesta instância.
var errCloudNoAgentSession = errors.New("cloud call: agent has no open softphone session")

// errCloudCallTaken: a ligação recebida já foi atendida por outro atendente.
var errCloudCallTaken = errors.New("cloud call: call already answered")

// errCloudMediaNegotiation: a negociação de mídia com a Meta falhou.
var errCloudMediaNegotiation = errors.New("cloud call: media negotiation failed")

var (
	cloudMediaOnce   sync.Once
	cloudMediaAPIVal *webrtc.API
	cloudMediaAPIErr error
)

// cloudMediaAPI monta a API do pion para a perna com a Meta, uma vez por processo.
//
// Separada da API do navegador de propósito. A do navegador multiplexa uma porta pública e
// anuncia o IP público, porque é o navegador que chega até nós. Aqui é o contrário: a Meta é
// ICE-lite e quem inicia os checks somos nós, então portas efêmeras de saída bastam — foi
// assim que a prova de mídia estabeleceu áudio atrás de NAT.
func cloudMediaAPI() (*webrtc.API, error) {
	cloudMediaOnce.Do(func() {
		engine := &webrtc.MediaEngine{}
		if err := engine.RegisterCodec(webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{
				MimeType:    webrtc.MimeTypeOpus,
				ClockRate:   cloudOpusClockRate,
				Channels:    2,
				SDPFmtpLine: "minptime=10;useinbandfec=1",
			},
			PayloadType: 111,
		}, webrtc.RTPCodecTypeAudio); err != nil {
			cloudMediaAPIErr = err
			return
		}

		settings := webrtc.SettingEngine{}
		settings.LoggerFactory = logging.NewDefaultLoggerFactory()
		// O lado da empresa é o cliente DTLS (`a=setup:active`), como a Meta exige.
		if err := settings.SetAnsweringDTLSRole(webrtc.DTLSRoleClient); err != nil {
			cloudMediaAPIErr = err
			return
		}
		// A mesma restrição de interface da mídia do navegador: em contêiner com várias
		// redes, só a interface que sai para a internet chega à Meta.
		settings.SetIPFilter(softphone.allowsMediaIP)

		cloudMediaAPIVal = webrtc.NewAPI(
			webrtc.WithMediaEngine(engine),
			webrtc.WithSettingEngine(settings),
		)
	})
	return cloudMediaAPIVal, cloudMediaAPIErr
}

// cloudContact identifica o contato da ligação. A Meta pode omitir o telefone e informar só o
// BSUID.
type cloudContact struct {
	JID   string `json:"jid,omitempty"`
	BSUID string `json:"bsuid,omitempty"`
	Name  string `json:"name,omitempty"`
}

// payload devolve o contato no formato dos quadros do softphone.
func (c cloudContact) payload() map[string]any {
	out := map[string]any{}
	if c.JID != "" {
		out["jid"] = c.JID
	}
	if c.BSUID != "" {
		out["bsuid"] = c.BSUID
	}
	if c.Name != "" {
		out["name"] = c.Name
	}
	return out
}

// cloudCall é uma ligação da Cloud API conduzida por um atendente.
type cloudCall struct {
	InstanceID string
	LegID      string
	AgentID    string
	Direction  CallDirection
	Contact    cloudContact
	// Record diz se a gravação foi concedida pela cota (FR-030). Pedida e não concedida não
	// grava nada.
	Record bool

	mu          sync.Mutex
	callID      string
	state       CallState
	established bool
	ended       bool
	leg         *cloudLeg
	bridge      *liveAudioBridge
	source      meowcaller.AudioSource
	sink        meowcaller.AudioSink
	recorder    *callRecorder
}

// CallID devolve o identificador da Meta, vazio até o `connect` na ligação feita.
func (c *cloudCall) CallID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.callID
}

func (c *cloudCall) setCallID(callID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.callID = callID
}

// conductingID é o identificador que a sessão do atendente guarda: o `callId` quando existe,
// e o `legId` antes dele.
func (c *cloudCall) conductingID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.callID != "" {
		return c.callID
	}
	return c.LegID
}

func (c *cloudCall) isEstablished() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.established && !c.ended
}

func (c *cloudCall) currentSource() meowcaller.AudioSource {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.source
}

func (c *cloudCall) currentSink() meowcaller.AudioSink {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sink
}

// cloudLeg é a `PeerConnection` com a Meta.
type cloudLeg struct {
	pc      *webrtc.PeerConnection
	track   *webrtc.TrackLocalStaticSample
	encoder *opusEncoder

	done      chan struct{}
	closeOnce sync.Once
}

func (l *cloudLeg) close() {
	if l == nil {
		return
	}
	l.closeOnce.Do(func() {
		close(l.done)
		if l.pc != nil {
			_ = l.pc.Close()
		}
	})
}

// cloudCallEngine conduz as pernas de mídia. Não guarda estado: o estado vive nos registros
// (`cloudCallRegistry`, `softphoneRegistry`), e o motor só sabe emitir eventos ao manager.
type cloudCallEngine struct {
	emit func(instanceID string, payload map[string]any)
}

// cloudCallEmitOverride substitui a entrega ao manager nos testes.
var cloudCallEmitOverride func(instanceID string, payload map[string]any)

// cloudEngine devolve o motor deste servidor.
func (s *server) cloudEngine() *cloudCallEngine {
	if cloudCallEmitOverride != nil {
		return &cloudCallEngine{emit: cloudCallEmitOverride}
	}
	return &cloudCallEngine{emit: s.emitCloudCallEvent}
}

// cloudAgentSession devolve a sessão aberta do atendente numa instância `cloud_api`.
func cloudAgentSession(instanceID, agentID string) (*agentSession, error) {
	session := GetSoftphoneRegistry().session(instanceID, agentID)
	if session == nil || !session.IsCloud() || session.State() != sessionStateConnected {
		return nil, errCloudNoAgentSession
	}
	return session, nil
}

// newLeg cria a `PeerConnection` com a Meta e arma os dois sentidos da mídia.
func (e *cloudCallEngine) newLeg(call *cloudCall) (*cloudLeg, error) {
	api, err := cloudMediaAPI()
	if err != nil {
		return nil, err
	}
	// Sem STUN nem TURN: a Meta é ICE-lite com IP público, e o nosso lado inicia os checks.
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, err
	}
	leg := &cloudLeg{pc: pc, done: make(chan struct{})}

	encoder, err := newOpusEncoder()
	if err != nil {
		leg.close()
		return nil, err
	}
	leg.encoder = encoder

	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: cloudOpusClockRate, Channels: 2},
		"audio", "zapperhub-cloud-call",
	)
	if err != nil {
		leg.close()
		encoder.Close()
		return nil, err
	}
	sender, err := pc.AddTrack(track)
	if err != nil {
		leg.close()
		encoder.Close()
		return nil, err
	}
	leg.track = track

	// Esvazia o RTCP recebido: sem leitura, o pion não processa os relatórios da Meta.
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := sender.Read(buf); err != nil {
				return
			}
		}
	}()

	pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		e.receiveFromMeta(call, remote)
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		// `failed` é terminal; `disconnected` pode voltar sozinho e não derruba a ligação.
		if state == webrtc.PeerConnectionStateFailed {
			e.mediaLost(call, "media-failed")
		}
	})

	go e.sendToMeta(call, leg)
	return leg, nil
}

// gather aplica a descrição local e espera a coleta terminar.
func gatherLocal(pc *webrtc.PeerConnection, desc webrtc.SessionDescription) (string, error) {
	done := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(desc); err != nil {
		return "", err
	}
	select {
	case <-done:
	case <-time.After(cloudGatherTimeout):
		log.Warn().Msg("Cloud call ICE gathering timed out; answering with what was gathered")
	}
	local := pc.LocalDescription()
	if local == nil {
		return "", errors.New("cloud call: no local description after gathering")
	}
	return local.SDP, nil
}

// sendToMeta envia a voz do atendente em quadros de 20 ms, só depois de `established`.
//
// Antes disso a perna existe mas não fala: o contato ainda não atendeu (ligação feita) ou a
// Meta ainda não confirmou o atendimento (ligação recebida). O laço nunca bloqueia na ponte:
// `ReadFrame` devolve silêncio quando não há áudio.
func (e *cloudCallEngine) sendToMeta(call *cloudCall, leg *cloudLeg) {
	ticker := time.NewTicker(cloudFrameDuration)
	defer ticker.Stop()
	defer leg.encoder.Close()

	var pending []float32
	for {
		select {
		case <-leg.done:
			return
		case <-ticker.C:
		}
		if !call.isEstablished() {
			pending = pending[:0]
			continue
		}
		if len(pending) < cloudFrameSamples {
			frame := silentFrame
			if source := call.currentSource(); source != nil {
				if read, err := source.ReadFrame(); err == nil && len(read) > 0 {
					frame = read
				}
			}
			pending = append(pending, frame...)
		}
		chunk := pending[:cloudFrameSamples]
		packet, err := leg.encoder.EncodeFrame(chunk)
		pending = pending[cloudFrameSamples:]
		if err != nil {
			log.Debug().Err(err).Msg("Cloud call could not encode a frame for Meta")
			continue
		}
		if err := leg.track.WriteSample(media.Sample{Data: packet, Duration: cloudFrameDuration}); err != nil {
			if errors.Is(err, io.ErrClosedPipe) {
				return
			}
		}
	}
}

// receiveFromMeta decodifica a voz do contato e a entrega à ponte em quadros de 60 ms.
//
// Pacote corrompido é descartado, nunca encerra a leitura: uma ligação que cai por causa de
// um pacote é uma ligação que cai.
func (e *cloudCallEngine) receiveFromMeta(call *cloudCall, remote *webrtc.TrackRemote) {
	decoder, err := newOpusDecoder()
	if err != nil {
		log.Error().Err(err).Msg("Cloud call could not create opus decoder")
		return
	}
	defer decoder.Close()

	var acc []float32
	for {
		packet, _, err := remote.ReadRTP()
		if err != nil {
			return
		}
		if len(packet.Payload) == 0 {
			continue
		}
		samples, err := decoder.Decode(packet.Payload)
		if err != nil {
			continue
		}
		acc = append(acc, samples...)
		for len(acc) >= meowcaller.FrameSamples {
			frame := make([]float32, meowcaller.FrameSamples)
			copy(frame, acc[:meowcaller.FrameSamples])
			acc = acc[meowcaller.FrameSamples:]
			if sink := call.currentSink(); sink != nil {
				_ = sink.WriteFrame(frame)
			}
		}
	}
}

// attach liga a ponte do atendente à ligação. Toda ligação nova começa com o microfone ativo
// (FR-028), sem o áudio acumulado antes dela.
func attachCloudCall(session *agentSession, call *cloudCall) {
	bridge := session.Bridge()
	bridge.Reset()
	bridge.SetMuted(false)
	call.mu.Lock()
	call.bridge = bridge
	call.source = bridge
	call.sink = bridge
	call.mu.Unlock()
	session.setConductingCall(call.conductingID())
}

// offer reserva a vaga do atendente e produz a oferta SDP para a Meta (ligação feita).
func (e *cloudCallEngine) offer(instanceID, agentID string, contact cloudContact, record bool) (*cloudCall, string, error) {
	session, err := cloudAgentSession(instanceID, agentID)
	if err != nil {
		return nil, "", err
	}

	call := &cloudCall{
		InstanceID: instanceID,
		AgentID:    agentID,
		Direction:  CallDirectionBusinessInitiated,
		Contact:    contact,
		Record:     record,
		state:      CallStateRinging,
	}
	if err := GetCloudCallRegistry().reserve(call); err != nil {
		return nil, "", err
	}

	leg, err := e.newLeg(call)
	if err != nil {
		GetCloudCallRegistry().release(call)
		log.Error().Err(err).Str("instanceID", instanceID).Msg("Cloud call leg could not be created")
		return nil, "", errCloudMediaNegotiation
	}
	call.mu.Lock()
	call.leg = leg
	call.mu.Unlock()

	offer, err := leg.pc.CreateOffer(nil)
	if err == nil {
		var sdp string
		if sdp, err = gatherLocal(leg.pc, offer); err == nil {
			attachCloudCall(session, call)
			publishCloudLineState(instanceID)
			log.Info().Str("instanceID", instanceID).Str("agentID", agentID).Str("leg_id", call.LegID).
				Msg("Cloud call offer created")
			return call, sdp, nil
		}
	}
	leg.close()
	GetCloudCallRegistry().release(call)
	log.Error().Err(err).Str("instanceID", instanceID).Msg("Cloud call offer could not be created")
	return nil, "", errCloudMediaNegotiation
}

// remoteAnswer aplica a resposta SDP da Meta à perna da ligação feita e associa o `callId`.
func (e *cloudCallEngine) remoteAnswer(instanceID, legID, callID, answer string) error {
	call := GetCloudCallRegistry().find(instanceID, legID)
	if call == nil {
		return errCloudCallNotFound
	}
	previous := call.conductingID()
	if callID != "" {
		if _, err := GetCloudCallRegistry().bindCallID(instanceID, call.LegID, callID); err != nil {
			return err
		}
		if session := GetSoftphoneRegistry().session(instanceID, call.AgentID); session != nil &&
			session.ConductingCall() == previous {
			session.setConductingCall(callID)
		}
	}

	call.mu.Lock()
	leg := call.leg
	call.mu.Unlock()
	if leg == nil {
		return errCloudCallNotFound
	}
	if err := leg.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		log.Warn().Err(err).Str("instanceID", instanceID).Str("leg_id", call.LegID).
			Msg("Cloud call answer refused by the media stack")
		return errCloudMediaNegotiation
	}
	return nil
}

// accept produz a resposta SDP para a oferta da Meta (ligação recebida).
func (e *cloudCallEngine) accept(instanceID, callID, agentID, offerSDP string, contact cloudContact, record bool) (*cloudCall, string, error) {
	session, err := cloudAgentSession(instanceID, agentID)
	if err != nil {
		return nil, "", err
	}
	if GetCloudCallRegistry().find(instanceID, callID) != nil {
		return nil, "", errCloudCallTaken
	}

	call := &cloudCall{
		InstanceID: instanceID,
		AgentID:    agentID,
		Direction:  CallDirectionUserInitiated,
		Contact:    contact,
		Record:     record,
		callID:     callID,
		state:      CallStateRinging,
	}
	if err := GetCloudCallRegistry().reserve(call); err != nil {
		return nil, "", err
	}

	leg, err := e.newLeg(call)
	if err != nil {
		GetCloudCallRegistry().release(call)
		log.Error().Err(err).Str("instanceID", instanceID).Msg("Cloud call leg could not be created")
		return nil, "", errCloudMediaNegotiation
	}
	call.mu.Lock()
	call.leg = leg
	call.mu.Unlock()

	fail := func(err error) (*cloudCall, string, error) {
		leg.close()
		GetCloudCallRegistry().release(call)
		log.Warn().Err(err).Str("instanceID", instanceID).Str("call_id", callID).
			Msg("Cloud call answer could not be created")
		return nil, "", errCloudMediaNegotiation
	}

	if err := leg.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offerSDP}); err != nil {
		return fail(err)
	}
	answer, err := leg.pc.CreateAnswer(nil)
	if err != nil {
		return fail(err)
	}
	sdp, err := gatherLocal(leg.pc, answer)
	if err != nil {
		return fail(err)
	}

	attachCloudCall(session, call)
	publishCloudLineState(instanceID)
	log.Info().Str("instanceID", instanceID).Str("agentID", agentID).Str("call_id", callID).
		Msg("Cloud call answer created")
	return call, sdp, nil
}

// established libera o envio de mídia e começa a gravação concedida, uma vez.
func (e *cloudCallEngine) established(instanceID, id string) error {
	call := GetCloudCallRegistry().find(instanceID, id)
	if call == nil {
		return errCloudCallNotFound
	}

	call.mu.Lock()
	if call.established || call.ended {
		call.mu.Unlock()
		return nil
	}
	call.established = true
	call.state = CallStateActive
	bridge, record := call.bridge, call.Record
	call.mu.Unlock()

	if bridge != nil {
		// O que a ponte acumulou enquanto tocava é anterior à conversa.
		bridge.Reset()
	}
	if record {
		e.startRecording(call)
	}

	log.Info().Str("instanceID", instanceID).Str("call_id", call.conductingID()).Msg("Cloud call established")
	publishCloudCallState(call, CallStateActive, "")
	return nil
}

// startRecording põe o gravador nos dois sentidos da ponte (FR-030). Falhar aqui não derruba
// a ligação: o cliente sabe pelo evento de gravação indisponível.
func (e *cloudCallEngine) startRecording(call *cloudCall) {
	recorder, err := newCallRecorder(call.InstanceID, call.conductingID())
	if err != nil {
		log.Warn().Err(err).Str("instanceID", call.InstanceID).Str("call_id", call.conductingID()).
			Msg("Cloud call recording could not be started — call continues without it")
		e.emitRecordingFailed(call, "STORAGE_FAILED")
		return
	}
	call.mu.Lock()
	call.recorder = recorder
	if call.bridge != nil {
		// O gravador é o relógio: a voz do contato avança as duas trilhas, e a voz do
		// atendente ocupa o lugar correspondente na trilha local.
		call.sink = recorder.TeeSink(call.bridge)
		call.source = recorder.WrapSource(call.bridge)
	}
	call.mu.Unlock()
	log.Info().Str("instanceID", call.InstanceID).Str("call_id", call.conductingID()).Msg("Cloud call recording started")
}

// end encerra a ligação por comando do manager. Idempotente: ligação desconhecida ou já
// encerrada não é erro.
func (e *cloudCallEngine) end(instanceID, id, reason string) {
	call := GetCloudCallRegistry().find(instanceID, id)
	if call == nil {
		return
	}
	e.finish(call, cloudEndOutcome(reason))
}

// mediaLost encerra a ligação cuja mídia caiu e avisa o manager, que encerra na Meta.
func (e *cloudCallEngine) mediaLost(call *cloudCall, reason string) {
	call.mu.Lock()
	ended := call.ended
	call.mu.Unlock()
	if ended {
		return
	}
	log.Warn().Str("instanceID", call.InstanceID).Str("call_id", call.conductingID()).Str("reason", reason).
		Msg("Cloud call media lost")
	e.emit(call.InstanceID, map[string]any{
		"type": "CloudCallMediaLost",
		"event": map[string]any{
			"CallID":    call.CallID(),
			"LegID":     call.LegID,
			"AgentID":   call.AgentID,
			"Reason":    reason,
			"Timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	})
	e.finish(call, CallOutcomeFailed)
}

// agentLost encerra a ligação do atendente que não voltou no período de graça (FR-039).
func (e *cloudCallEngine) agentLost(instanceID string, session *agentSession) {
	call := GetCloudCallRegistry().agentCall(instanceID, session.Agent().ID)
	if call == nil {
		return
	}
	e.mediaLost(call, callEndReasonAgentLost)
}

// finish libera a vaga, fecha a perna, publica o fim ao atendente e entrega a gravação. Uma
// vez só.
func (e *cloudCallEngine) finish(call *cloudCall, outcome CallOutcome) {
	call.mu.Lock()
	if call.ended {
		call.mu.Unlock()
		return
	}
	call.ended = true
	call.state = CallStateEnded
	leg := call.leg
	call.mu.Unlock()

	conducting := call.conductingID()
	GetCloudCallRegistry().release(call)
	leg.close()

	log.Info().Str("instanceID", call.InstanceID).Str("call_id", conducting).Str("outcome", string(outcome)).
		Msg("Cloud call ended")

	publishCloudCallState(call, CallStateEnded, outcome)

	if session := GetSoftphoneRegistry().session(call.InstanceID, call.AgentID); session != nil {
		current := session.ConductingCall()
		if current == conducting || current == call.LegID {
			session.setConductingCall("")
			if bridge := session.Bridge(); bridge != nil {
				bridge.Reset()
			}
			// A ligação acabou durante a graça: o temporizador não pode sobrescrever o
			// desfecho verdadeiro com uma falha (FR-041).
			cancelGrace(session)
		}
	}
	publishCloudLineState(call.InstanceID)
	e.finishRecording(call)
}

// cloudEndOutcome lê o motivo enviado pelo manager, que é o desfecho registrado.
func cloudEndOutcome(reason string) CallOutcome {
	switch outcome := CallOutcome(reason); outcome {
	case CallOutcomeCompleted, CallOutcomeRejected, CallOutcomeMissed, CallOutcomeUnavailable,
		CallOutcomeTerminatedByBusiness, CallOutcomeFailed:
		return outcome
	}
	return CallOutcomeFailed
}

// finishRecording fecha a captura e a entrega ao manager, como no `device`.
func (e *cloudCallEngine) finishRecording(call *cloudCall) {
	call.mu.Lock()
	recorder := call.recorder
	call.recorder = nil
	call.mu.Unlock()
	if recorder == nil {
		return
	}

	result := recorder.Close()
	if result.DurationSeconds == 0 {
		recorder.Discard()
		e.emitRecordingFailed(call, "STORAGE_FAILED")
		return
	}
	remoteToken, localToken, err := publishRecordingTracks(result)
	if err != nil {
		recorder.Discard()
		e.emitRecordingFailed(call, "STORAGE_FAILED")
		return
	}
	e.emit(call.InstanceID, map[string]any{
		"type": "CallRecordingReady",
		"event": map[string]any{
			"CallID":           call.CallID(),
			"RemoteTrackToken": remoteToken,
			"LocalTrackToken":  localToken,
			"DurationSeconds":  result.DurationSeconds,
			"Truncated":        result.Truncated,
			"Timestamp":        time.Now().UTC().Format(time.RFC3339),
		},
	})
}

func (e *cloudCallEngine) emitRecordingFailed(call *cloudCall, reason string) {
	e.emit(call.InstanceID, map[string]any{
		"type": "CallRecordingFailed",
		"event": map[string]any{
			"CallID":    call.CallID(),
			"Reason":    reason,
			"Timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// publishCloudCallState entrega a transição só ao atendente que conduz a ligação.
//
// No `device` o estado vai a todas as sessões, porque a instância tem uma ligação só. Aqui
// cada atendente tem a sua, e o componente trata todo `call.state` como a própria ligação:
// entregar a ligação de outro atendente encerraria a ligação errada na tela.
func publishCloudCallState(call *cloudCall, state CallState, outcome CallOutcome) {
	session := GetSoftphoneRegistry().session(call.InstanceID, call.AgentID)
	if session == nil {
		return
	}
	data := map[string]any{
		"callId":    call.conductingID(),
		"state":     softphoneCallState(state),
		"direction": string(call.Direction),
		"contact":   call.Contact.payload(),
		"at":        time.Now().UTC().Format(time.RFC3339),
	}
	if state == CallStateEnded {
		data["endedReason"] = softphoneEndedReason(outcome)
	}
	if call.Record {
		data["recording"] = map[string]any{"requested": true, "granted": true}
	}
	session.notify(map[string]any{"t": "call.state", "d": data})
}

// cloudWebhookClient entrega os eventos do motor ao manager.
var cloudWebhookClient = &http.Client{Timeout: 10 * time.Second}

// emitCloudCallEvent entrega um evento ao webhook da instância, que aponta para o manager.
//
// Não passa por `sendEventWithWebHook`: aquele caminho depende do cliente de WhatsApp da
// instância, e a instância `cloud_api` não tem sessão de WhatsApp neste servidor. O corpo é o
// mesmo envelope que o manager lê dos demais eventos: `type`, `event`, `instanceName` e
// `serverId`.
func (s *server) emitCloudCallEvent(instanceID string, payload map[string]any) {
	var webhook string
	if err := s.db.Get(&webhook, "SELECT webhook FROM users WHERE token=$1 LIMIT 1", instanceID); err != nil || webhook == "" {
		log.Warn().Str("instanceID", instanceID).Interface("type", payload["type"]).
			Msg("Cloud call event dropped: instance has no webhook on this server")
		return
	}
	payload["instanceName"] = instanceID
	enrichWebhookPayload(payload)
	body, err := json.Marshal(payload)
	if err != nil {
		log.Error().Err(err).Msg("Cloud call event could not be encoded")
		return
	}

	safeGo("cloudCallEvent", func() {
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
			resp, err := cloudWebhookClient.Post(webhook, "application/json", bytes.NewReader(body))
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 500 {
					return
				}
				err = fmt.Errorf("status %d", resp.StatusCode)
			}
			log.Warn().Err(err).Str("instanceID", instanceID).Int("attempt", attempt+1).
				Interface("type", payload["type"]).Msg("Cloud call event delivery failed")
		}
	})
}
