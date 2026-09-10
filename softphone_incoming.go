package main

import (
	"time"

	"github.com/rs/zerolog/log"
)

// Sinalização de chamada entrante aos atendentes (feature 021, US4, research §R9).
//
// Todo o leque acontece em um mapa em memória do mesmo processo que arbitra a vaga. Não há
// barramento, lock distribuído nem coordenação entre réplicas — e essa é justamente a razão
// de a sessão do atendente terminar no `wuzapi` e não no `manager`.

// Motivos de cessação da sinalização (FR-024).
const (
	// incomingClearedAnswered: outro atendente aceitou. **Não é erro** — é o resultado
	// normal de uma corrida que exatamente um tinha de vencer (US4-AS3).
	incomingClearedAnswered = "ANSWERED_ELSEWHERE"
	// incomingClearedRejected: um atendente recusou pelo componente (US4-AS5).
	incomingClearedRejected = "REJECTED"
	// incomingClearedAbandoned: o contato desistiu antes de qualquer aceite (US4-AS6).
	incomingClearedAbandoned = "ABANDONED"
)

// publishIncomingCall sinaliza a oferta a todos os atendentes conectados (FR-021).
//
// Sem sessão alguma aberta, isto é um laço sobre um mapa vazio — e é exatamente assim que
// FR-025 é cumprida: o caminho da `020` segue intocado, e o cliente que consome chamadas
// entrantes por webhook não percebe que o softphone existe.
func publishIncomingCall(instanceID, callID, peer string) {
	sessions := GetSoftphoneRegistry().sessions(instanceID)
	if len(sessions) == 0 {
		return
	}

	frame := map[string]any{
		"t": "call.incoming",
		"d": map[string]any{
			"callId":  callID,
			"contact": map[string]any{"jid": peer},
			"at":      time.Now().UTC().Format(time.RFC3339),
		},
	}

	for _, session := range sessions {
		session.notify(frame)
	}

	log.Info().
		Str("instanceID", instanceID).
		Str("call_id", callID).
		Int("agents", len(sessions)).
		Msg("Incoming call signalled to softphone agents")
}

// publishIncomingCleared faz todos os componentes pararem de sinalizar (FR-024).
func publishIncomingCleared(instanceID, callID, reason string) {
	sessions := GetSoftphoneRegistry().sessions(instanceID)
	if len(sessions) == 0 {
		return
	}

	frame := map[string]any{
		"t": "call.incoming.cleared",
		"d": map[string]any{"callId": callID, "reason": reason},
	}

	for _, session := range sessions {
		session.notify(frame)
	}
}

// incomingOfferOutcome classifica por que uma oferta não está mais disponível.
//
// A distinção existe por causa da tela do atendente, e não da correção do servidor. Quem
// perde a corrida precisa ler "a chamada foi atendida por outro atendente" — situação normal
// de uma operação com vários atendentes. Ler "chamada não encontrada" faria a pessoa
// concluir que o sistema falhou, e abrir chamado por algo que funcionou exatamente como
// deveria (US4-AS4).
type incomingOfferResult int

const (
	// incomingOfferUnknown: nunca houve oferta com este identificador.
	incomingOfferUnknown incomingOfferResult = iota
	// incomingOfferTaken: a oferta virou chamada, conduzida por outro atendente.
	incomingOfferTaken
)

func incomingOfferOutcome(instanceID, callID string) incomingOfferResult {
	if current := GetCallRegistry().current(instanceID); current != nil && current.CallID == callID {
		return incomingOfferTaken
	}
	return incomingOfferUnknown
}

// publishLineState publica a disponibilidade corrente da linha (FR-033, FR-034).
//
// Chamado **depois** de o lock do `callRegistry` ser liberado, sempre. Publicar de dentro do
// lock faria a escrita em N sockets — que pode bloquear — segurar o mutex que arbitra a vaga
// da instância, e uma chamada nova ficaria esperando um navegador lento terminar de ler.
func publishLineState(instanceID string) {
	registry := GetSoftphoneRegistry()
	if len(registry.sessions(instanceID)) == 0 {
		return
	}
	registry.broadcast(instanceID, map[string]any{
		"t": "line.update",
		"d": lineStatePayload(instanceID),
	})
}
