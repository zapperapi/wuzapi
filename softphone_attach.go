package main

import (
	"errors"

	"github.com/rs/zerolog/log"
)

// Ligação entre a sessão do atendente e a chamada (feature 021, research §R4).
//
// O ponto delicado é que a chamada e a sessão têm ciclos de vida independentes: a chamada
// pertence ao `callRegistry`, a sessão ao `softphoneRegistry`, e uma sobrevive à outra nos
// dois sentidos — o atendente cai e a chamada continua no período de graça (FR-037); a
// chamada termina e a sessão segue aberta esperando a próxima.
//
// A ponte é o que costura os dois sem acoplá-los.

var errNoAgentSession = errors.New("softphone: agent has no open session on this instance")

// attachAgentToCall instala a ponte de áudio do atendente na chamada.
//
// Passa por `liveCall.play`, e não direto em `call.Play`, de propósito: é `play` que mantém o
// invariante de reprodução única (`liveCall.player`) e que **tee-a a fonte para o gravador**
// quando há gravação. Ir direto ao meowcaller ganharia duas linhas e perderia a gravação da
// perna local — a voz do atendente sumiria do arquivo, que é justamente o que US9-AS2 exige
// que esteja lá.
//
// O `cleanup` é vazio porque não há arquivo temporário a remover: a fonte é a ponte, e ela
// vive enquanto a sessão viver.
func attachAgentToCall(instanceID, agentID string, lc *liveCall) error {
	session := GetSoftphoneRegistry().session(instanceID, agentID)
	if session == nil {
		return errNoAgentSession
	}

	bridge := session.Bridge()
	if bridge == nil {
		return errNoAgentSession
	}

	// Descarta o que estiver na fila antes de começar: são amostras capturadas enquanto
	// ninguém falava com ninguém, e reproduzi-las entregaria ao contato uma fala anterior
	// à própria chamada.
	bridge.Reset()

	// Toda chamada nova começa com o microfone ativo (FR-028). A ponte é da sessão e
	// sobrevive entre chamadas, então o mudo esquecido na anterior precisa ser desfeito
	// aqui — senão o atendente começaria a próxima mudo, sem saber por quê. É a anexação
	// que zera, e não o `Reset`, porque só ela sabe que isto é um começo e não uma
	// reconexão no meio de uma conversa.
	bridge.SetMuted(false)

	if _, err := lc.play(bridge, func() {}); err != nil {
		return err
	}

	// A voz do contato passa a chegar à ponte, que a encaminha ao navegador. Substitui o
	// sink, e é por isso que o tee da gravação precisa existir (research §R6): sem ele, uma
	// chamada ao vivo gravada perderia a perna remota.
	lc.receive(bridge)

	session.setConductingCall(lc.CallID)

	log.Info().
		Str("instanceID", instanceID).
		Str("agentID", agentID).
		Str("call_id", lc.CallID).
		Msg("Softphone agent attached to call")

	return nil
}

// detachAgentFromCall desassocia a sessão da chamada encerrada.
//
// Não fecha a ponte: a sessão continua aberta e a próxima chamada reusa o mesmo objeto. O
// que se descarta é o áudio pendente, pelo mesmo motivo da anexação — ele pertence a uma
// conversa que acabou.
func detachAgentFromCall(instanceID, callID string) {
	for _, session := range GetSoftphoneRegistry().sessions(instanceID) {
		if session.ConductingCall() != callID {
			continue
		}
		session.setConductingCall("")
		if bridge := session.Bridge(); bridge != nil {
			bridge.Reset()
		}

		// FR-041: se a chamada acabou enquanto o atendente estava em período de graça — o
		// contato desligou, tipicamente — o temporizador precisa ser desarmado. Deixá-lo
		// vivo faria o encerramento por falha sobrescrever o desfecho verdadeiro, e o
		// histórico atribuiria ao sistema uma queda que foi o contato desligando.
		cancelGrace(session)
	}
}
