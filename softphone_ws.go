package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/rs/zerolog/log"
)

// Sessão de tempo real do softphone (feature 021).
//
// Carrega sinalização de mídia, estado e notificação — nunca áudio, que trafega por WebRTC.
// O contrato normativo dos quadros está em
// specs/021-audio-bidirecional/contracts/softphone-ws.md.

const (
	// softphoneAuthDeadline é o prazo para o primeiro quadro `session.open`.
	//
	// A conexão abre sem credencial porque o navegador não permite cabeçalho personalizado
	// no handshake de WebSocket, e a query string apareceria em log de acesso e em proxy —
	// o que colocaria uma credencial em log (Princípio VI). O preço é uma janela curta de
	// socket anônimo, fechada por este prazo.
	softphoneAuthDeadline = 5 * time.Second

	// softphoneReadLimit limita o quadro recebido. Ofertas SDP são o maior quadro legítimo
	// e ficam bem abaixo disso; o limite existe para que um cliente hostil não consuma
	// memória do processo que hospeda as sessões de WhatsApp.
	softphoneReadLimit = 256 * 1024

	// softphoneWriteTimeout limita a escrita de um quadro. Sem ele, um cliente que para de
	// ler travaria a goroutine que publica disponibilidade de linha para todos os outros.
	softphoneWriteTimeout = 5 * time.Second
)

// softphoneFrame é o envelope de todo quadro: discriminador no topo, correlação opcional,
// dados no `d`.
type softphoneFrame struct {
	T  string          `json:"t"`
	ID string          `json:"id,omitempty"`
	D  json.RawMessage `json:"d,omitempty"`
}

type sessionOpenData struct {
	Token string `json:"token"`
}

type mediaOfferData struct {
	SDP string `json:"sdp"`
}

// SoftphoneWS trata a rota `/softphone`.
//
// Registrada **fora** da cadeia `authalice`: o socket do atendente tem autenticação própria
// e não alcança nenhuma operação da instância além do softphone (FR-061).
func (s *server) SoftphoneWS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !softphone.enabled {
			http.Error(w, "softphone is not enabled on this server", http.StatusNotImplemented)
			return
		}

		// A validação de origem não acontece aqui: uma lista fixa por servidor não serve a
		// uma frota multi-tenant, onde cada instância hospedada neste mesmo processo pode
		// ter um CRM em um domínio diferente. `InsecureSkipVerify` aceita o handshake de
		// qualquer origem, e `authenticateSoftphone` confere o cabeçalho `Origin` contra a
		// claim que o manager estampou no token — a única fonte que sabe qual origem é
		// esperada *para esta instância*.
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			log.Debug().Err(err).Msg("Softphone websocket handshake refused")
			return
		}
		conn.SetReadLimit(softphoneReadLimit)

		s.serveSoftphoneSession(r.Context(), conn, r.Header.Get("Origin"))
	}
}

// serveSoftphoneSession conduz uma conexão do handshake ao encerramento.
func (s *server) serveSoftphoneSession(ctx context.Context, conn *websocket.Conn, origin string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	session, instanceID, err := s.authenticateSoftphone(ctx, conn, origin)
	if err != nil {
		return
	}
	defer func() {
		_ = conn.Close(websocket.StatusNormalClosure, "")

		// Feature 021: se o atendente conduzia uma chamada, a sessão **não** morre aqui —
		// ela entra no período de graça, e a conversa com o contato continua enquanto ele
		// tenta voltar (FR-037). Uma sessão ociosa é fechada de imediato, porque não há
		// nada a preservar.
		//
		// A mídia é encerrada de qualquer forma: ela pertence a esta conexão, e a
		// reconexão negocia uma nova. A ponte de áudio, essa sim, sobrevive — é o que
		// permite retomar a mesma chamada (research §R4).
		session.closeMediaOnly()
		beginGrace(session, func() { s.endCallForLostAgent(instanceID, session) })

		log.Info().
			Str("instanceID", instanceID).
			Str("agentID", session.agent.ID).
			Str("state", session.State().String()).
			Msg("Softphone connection closed")
	}()

	for {
		frame, err := readSoftphoneFrame(ctx, conn)
		if err != nil {
			return
		}
		if !s.dispatchSoftphoneFrame(ctx, conn, session, instanceID, frame) {
			return
		}
	}
}

// authenticateSoftphone exige `session.open` dentro do prazo e abre a sessão.
func (s *server) authenticateSoftphone(
	ctx context.Context,
	conn *websocket.Conn,
	origin string,
) (*agentSession, string, error) {
	authCtx, cancel := context.WithTimeout(ctx, softphoneAuthDeadline)
	defer cancel()

	frame, err := readSoftphoneFrame(authCtx, conn)
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "session.open expected")
		return nil, "", err
	}
	if frame.T != "session.open" {
		writeSoftphoneError(ctx, conn, frame.ID, "AGENT_TOKEN_INVALID", "credencial inválida")
		_ = conn.Close(websocket.StatusPolicyViolation, "session.open expected")
		return nil, "", errors.New("softphone: first frame was not session.open")
	}

	var data sessionOpenData
	if err := json.Unmarshal(frame.D, &data); err != nil {
		writeSoftphoneError(ctx, conn, frame.ID, "AGENT_TOKEN_INVALID", "credencial inválida")
		_ = conn.Close(websocket.StatusPolicyViolation, "malformed session.open")
		return nil, "", err
	}

	agent, instanceID, err := parseAgentToken(data.Token)
	if err != nil {
		code := "AGENT_TOKEN_INVALID"
		if errors.Is(err, errAgentTokenScope) {
			code = "AGENT_TOKEN_SCOPE"
		}
		// A causa real fica no log; a resposta não distingue expirada de adulterada de
		// desconhecida (FR-009). O token nunca é registrado.
		log.Warn().Err(err).Msg("Softphone credential refused")
		writeSoftphoneError(ctx, conn, frame.ID, code, "credencial inválida")
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid credential")
		return nil, "", err
	}

	// A origem do handshake precisa bater com a que o manager estampou na credencial
	// (FR-009: uma única resposta para causas variadas — aqui não é diferente de token
	// adulterado, então usa o mesmo código, sem revelar qual das duas falhou).
	if !strings.EqualFold(origin, agent.Origin) {
		log.Warn().Str("instanceID", instanceID).Str("origin", origin).
			Msg("Softphone credential presented from an unexpected origin")
		writeSoftphoneError(ctx, conn, frame.ID, "AGENT_TOKEN_INVALID", "credencial inválida")
		_ = conn.Close(websocket.StatusPolicyViolation, "unexpected origin")
		return nil, "", errAgentTokenInvalid
	}

	// A instância precisa existir **neste** servidor e ter sessão ativa no WhatsApp
	// (FR-002). Uma credencial legítima apresentada ao servidor errado morre aqui.
	if _, err := s.resolveCallEngine(instanceID); err != nil {
		log.Warn().Str("instanceID", instanceID).Err(err).
			Msg("Softphone session refused: instance unavailable on this server")
		writeSoftphoneError(ctx, conn, frame.ID, "INSTANCE_NOT_CONNECTED",
			"a instância não tem sessão ativa no WhatsApp")
		_ = conn.Close(websocket.StatusPolicyViolation, "instance unavailable")
		return nil, "", err
	}

	// Retomar vem antes de abrir: uma sessão em período de graça guarda a ponte de áudio e a
	// chamada em curso, e abrir uma nova no lugar dela daria ao atendente um objeto vazio
	// enquanto o contato continuaria ouvindo silêncio até o fim (FR-038).
	resumed := GetSoftphoneRegistry().resume(instanceID, agent.ID)
	session := resumed
	if session == nil {
		session = GetSoftphoneRegistry().open(instanceID, agent)
	}

	session.attach(func(frame any) {
		writeSoftphoneFrame(context.Background(), conn, frame)
	})

	log.Info().
		Str("instanceID", instanceID).
		Str("agentID", agent.ID).
		Str("jti", agent.JTI).
		Bool("resumed", resumed != nil).
		Msg("Softphone session opened")

	ready := map[string]any{
		"agent":        softphoneAgentPayload(agent),
		"line":         lineStatePayload(instanceID),
		"graceSeconds": int(softphoneGracePeriod / time.Second),
	}
	// Retomada dentro do prazo: o componente precisa saber que voltou para **a mesma**
	// chamada, e não iniciar do zero. Sem isto ele mostraria o estado ocioso sobre uma
	// conversa que continua acontecendo (FR-038).
	if resumed != nil {
		if callID := resumed.ConductingCall(); callID != "" {
			ready["resumedCallId"] = callID
		}
	}
	writeSoftphoneFrame(ctx, conn, map[string]any{
		"t":  "session.ready",
		"id": frame.ID,
		"d":  ready,
	})

	return session, instanceID, nil
}

// dispatchSoftphoneFrame trata um quadro do cliente. Devolve false para encerrar a conexão.
func (s *server) dispatchSoftphoneFrame(
	ctx context.Context,
	conn *websocket.Conn,
	session *agentSession,
	instanceID string,
	frame softphoneFrame,
) bool {
	switch frame.T {
	case "ping":
		writeSoftphoneFrame(ctx, conn, map[string]any{"t": "pong", "id": frame.ID})

	case "session.refresh":
		var data sessionOpenData
		if err := json.Unmarshal(frame.D, &data); err != nil {
			writeSoftphoneError(ctx, conn, frame.ID, "AGENT_TOKEN_INVALID", "credencial inválida")
			return true
		}
		agent, tokenInstance, err := parseAgentToken(data.Token)
		// Renovação que falha **não** derruba a conversa em curso (FR-010): a chamada segue,
		// e apenas as operações seguintes ficam bloqueadas até uma credencial válida chegar.
		if err != nil || tokenInstance != instanceID || agent.ID != session.agent.ID {
			log.Warn().Str("instanceID", instanceID).Err(err).
				Msg("Softphone credential refresh refused; existing session kept")
			writeSoftphoneError(ctx, conn, frame.ID, "AGENT_TOKEN_INVALID", "credencial inválida")
			return true
		}
		writeSoftphoneFrame(ctx, conn, map[string]any{
			"t":  "session.ready",
			"id": frame.ID,
			"d": map[string]any{
				"agent":        softphoneAgentPayload(agent),
				"line":         lineStatePayload(instanceID),
				"graceSeconds": int(softphoneGracePeriod / time.Second),
			},
		})

	case "media.offer":
		var data mediaOfferData
		if err := json.Unmarshal(frame.D, &data); err != nil || data.SDP == "" {
			writeSoftphoneError(ctx, conn, frame.ID, "MEDIA_NEGOTIATION_FAILED",
				"oferta de mídia inválida")
			return true
		}
		media, answer, err := newSoftphoneMedia(data.SDP, session.Bridge())
		if err != nil {
			log.Error().Err(err).Str("instanceID", instanceID).
				Msg("Softphone media negotiation failed")
			writeSoftphoneError(ctx, conn, frame.ID, "MEDIA_NEGOTIATION_FAILED",
				"não foi possível estabelecer o áudio")
			return true
		}
		// Substitui a mídia anterior, se houver. É por aqui que a reconexão dentro do
		// período de graça passa: a ponte, a chamada e o gravador não são tocados
		// (FR-038, research §R4).
		session.setMedia(media)
		writeSoftphoneFrame(ctx, conn, map[string]any{
			"t":  "media.answer",
			"id": frame.ID,
			"d":  map[string]any{"sdp": answer},
		})

	case "mic.mute", "mic.unmute":
		muted := frame.T == "mic.mute"

		// V-12: silenciar exige chamada ativa. Sem ela não há o que silenciar, e aceitar em
		// silêncio deixaria o componente exibindo "mudo" sobre nada.
		if session.ConductingCall() == "" {
			writeSoftphoneError(ctx, conn, frame.ID, "CALL_NOT_AVAILABLE",
				"não há chamada ativa para silenciar")
			return true
		}

		bridge := session.Bridge()
		if bridge == nil {
			writeSoftphoneError(ctx, conn, frame.ID, "CALL_NOT_AVAILABLE",
				"não há chamada ativa para silenciar")
			return true
		}
		bridge.SetMuted(muted)

		log.Info().
			Str("instanceID", instanceID).
			Str("agentID", session.agent.ID).
			Str("call_id", session.ConductingCall()).
			Bool("muted", muted).
			Msg("Softphone microphone state changed")

		// O estado devolvido é o que o **servidor** aplicou, e não o que o cliente pediu:
		// é ele que cumpre FR-027, e é ele que o componente precisa exibir (FR-028).
		writeSoftphoneFrame(ctx, conn, map[string]any{
			"t":  "mic.state",
			"id": frame.ID,
			"d":  map[string]any{"muted": bridge.Muted()},
		})

	default:
		// Quadro desconhecido não derruba a sessão: um cliente mais novo que este servidor
		// pode mandar algo que ainda não tratamos, e encerrar por isso transformaria uma
		// incompatibilidade menor em queda de ligação.
		log.Debug().Str("type", frame.T).Msg("Softphone frame ignored")
	}
	return true
}

// softphoneAgentPayload monta o bloco de identidade dos quadros.
func softphoneAgentPayload(agent agentIdentity) map[string]any {
	payload := map[string]any{"id": agent.ID}
	if agent.DisplayName != "" {
		payload["displayName"] = agent.DisplayName
	}
	return payload
}

func readSoftphoneFrame(ctx context.Context, conn *websocket.Conn) (softphoneFrame, error) {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return softphoneFrame{}, err
	}
	var frame softphoneFrame
	if err := json.Unmarshal(data, &frame); err != nil {
		return softphoneFrame{}, err
	}
	return frame, nil
}

func writeSoftphoneFrame(ctx context.Context, conn *websocket.Conn, frame any) {
	body, err := json.Marshal(frame)
	if err != nil {
		log.Error().Err(err).Msg("Softphone frame could not be encoded")
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, softphoneWriteTimeout)
	defer cancel()
	if err := conn.Write(writeCtx, websocket.MessageText, body); err != nil {
		log.Debug().Err(err).Msg("Softphone frame could not be delivered")
	}
}

func writeSoftphoneError(ctx context.Context, conn *websocket.Conn, id, code, message string) {
	writeSoftphoneFrame(ctx, conn, map[string]any{
		"t":  "session.error",
		"id": id,
		"d":  map[string]any{"code": code, "message": message},
	})
}
