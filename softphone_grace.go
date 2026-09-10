package main

import (
	"time"

	"github.com/rs/zerolog/log"
)

// Período de graça do atendente (US8, FR-037 a FR-042, research §R10).
//
// A regra é uma só: **a chamada com o contato não morre porque o atendente sumiu.** Uma
// troca de rede, um Wi-Fi oscilando, um notebook que suspendeu por um instante — nada disso
// é razão para o contato ouvir a ligação cair e ter de ser chamado de novo.
//
// O que a graça compra são 15 segundos. Passados eles, a chamada termina com desfecho de
// falha, porque manter o contato ouvindo silêncio indefinidamente é pior do que encerrar.

// callEndReasonAgentLost é o motivo publicado quando a graça se esgota.
//
// Um motivo próprio, e não `connection-error`, porque ele descreve algo distinto: não foi a
// ligação com o contato que falhou, foi o atendente que não voltou. A distinção só existe no
// log e na tabela — o desfecho publicado ao cliente é `FAILED` nos dois casos, como FR-039
// exige.
const callEndReasonAgentLost = "agent-lost"

// beginGrace coloca a sessão em reconexão e agenda o encerramento.
//
// `endCall` é injetado porque quem sabe encerrar é o motor de chamadas, e amarrar este
// arquivo a ele tornaria a contabilidade da graça impossível de testar sem uma sessão de
// WhatsApp viva.
//
// Uma sessão **ociosa** não entra em graça: não há chamada a preservar, e mantê-la no
// registro faria a linha aparecer ocupada por um atendente que já foi embora.
func beginGrace(session *agentSession, endCall func()) {
	if session == nil {
		return
	}

	if session.ConductingCall() == "" {
		GetSoftphoneRegistry().close(session, closeReasonClientClosed)
		return
	}

	deadline := time.Now().Add(softphoneGracePeriod)
	if !session.enterGrace(deadline) {
		return
	}

	log.Info().
		Str("instanceID", session.instanceID).
		Str("agentID", session.agent.ID).
		Str("call_id", session.ConductingCall()).
		Dur("grace", softphoneGracePeriod).
		Msg("Softphone agent lost; call held during grace period")

	// A chamada continua ativa: o que o atendente vê é a sessão reconectando, e o que o
	// contato ouve é o silêncio que a ponte devolve enquanto não há mídia (FR-037).
	session.notify(map[string]any{
		"t": "session.reconnecting",
		"d": map[string]any{"graceUntil": deadline.UTC().Format(time.RFC3339)},
	})

	timer := time.AfterFunc(softphoneGracePeriod, func() {
		// Reconferir sob o estado corrente: entre o disparo e aqui, o atendente pode ter
		// voltado, ou o contato pode ter desligado. Nos dois casos não há nada a fazer.
		if session.State() != sessionStateReconnecting || session.ConductingCall() == "" {
			return
		}

		log.Warn().
			Str("instanceID", session.instanceID).
			Str("agentID", session.agent.ID).
			Str("call_id", session.ConductingCall()).
			Msg("Softphone grace period expired; ending the call")

		session.markClosed(closeReasonGraceExpired)
		GetSoftphoneRegistry().close(session, closeReasonGraceExpired)
		session.closeMedia()
		endCall()
	})

	session.setGraceTimer(timer)
}

// cancelGrace desarma o temporizador sem alterar o estado da sessão.
//
// Usado quando a chamada acaba por conta própria durante a graça — o contato desligou, a
// instância caiu. O desfecho já foi publicado por quem encerrou, com o motivo verdadeiro, e
// deixar o temporizador vivo sobrescreveria isso com uma falha que não houve (FR-041).
func cancelGrace(session *agentSession) {
	if session == nil {
		return
	}
	session.stopGraceTimer()
}

// endCallForLostAgent encerra a chamada que o atendente perdido conduzia (FR-039).
//
// Publica o desfecho pelo mesmo caminho de qualquer outro encerramento — `callEngine.finish`
// —, o que garante que a vaga é liberada, o webhook sai e o registro fecha exatamente como
// nas demais saídas. Um caminho paralelo aqui teria de repetir as quatro coisas e acabaria
// esquecendo uma.
func (s *server) endCallForLostAgent(instanceID string, session *agentSession) {
	callID := session.ConductingCall()
	if callID == "" {
		return
	}

	engine, err := s.resolveCallEngine(instanceID)
	if err != nil {
		// A instância caiu junto: não há chamada a encerrar, e a `020` já fecha registros
		// não terminais quando a sessão do WhatsApp se perde.
		log.Warn().Str("instanceID", instanceID).Err(err).
			Msg("Grace period expired but the instance is gone")
		return
	}

	lc, err := GetCallRegistry().get(instanceID, callID)
	if err != nil {
		// A chamada já acabou por conta própria durante a graça — o contato desligou, por
		// exemplo. O desfecho verdadeiro já foi publicado por quem a encerrou (FR-041).
		return
	}

	engine.finish(lc, callEndReasonAgentLost)
}
