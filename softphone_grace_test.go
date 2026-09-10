package main

import (
	"testing"
	"time"
)

// Período de graça (US8, FR-037 a FR-042).
//
// Determina se a feature aguenta uso real fora de um escritório com rede cabeada. A regra é
// uma só: **a chamada com o contato não morre porque o atendente sumiu** — ela espera 15
// segundos por ele.
//
// O que estes testes cobrem é a contabilidade: entrar na graça, sair dela, e o que acontece
// quando o prazo vence. O que eles **não** cobrem é o comportamento real de rede — se o
// navegador de fato reconecta em 3 s numa troca de Wi-Fi, e se o `PeerConnectionState` vai a
// `disconnected` quando deveria. Isso é o Cenário 8 do quickstart, com rede de verdade.

/** withShortGrace encurta o período de graça durante o teste. */
func withShortGrace(t *testing.T, d time.Duration) {
	t.Helper()
	previous := softphoneGracePeriod
	softphoneGracePeriod = d
	t.Cleanup(func() { softphoneGracePeriod = previous })
}

// FR-037 e US8-AS1: perder a sessão inicia a graça e **não** encerra a chamada.
func TestSessionLossEntersGraceWithoutEndingCall(t *testing.T) {
	withShortGrace(t, time.Hour) // longo: o teste observa a entrada, não o vencimento

	registry := GetSoftphoneRegistry()
	const instanceID = "inst_grace_enter"

	session := registry.open(instanceID, agentIdentity{ID: "op-1"})
	defer registry.close(session, closeReasonClientClosed)
	session.setConductingCall("call_1")

	var ended bool
	beginGrace(session, func() { ended = true })

	if got := session.State(); got != sessionStateReconnecting {
		t.Errorf("estado = %v, esperado %v", got, sessionStateReconnecting)
	}
	if ended {
		t.Error("a chamada foi encerrada ao perder a sessão; ela deveria esperar a graça (FR-037)")
	}
	if session.GraceUntil().IsZero() {
		t.Error("o prazo da graça não foi registrado")
	}
	// A sessão continua no registro: é o que permite a reconexão encontrá-la.
	if registry.session(instanceID, "op-1") != session {
		t.Error("a sessão saiu do registro durante a graça; a reconexão não a encontraria")
	}
}

// FR-038 e US8-AS2: reconectar dentro da graça retoma **a mesma chamada**.
//
// "Mesma chamada" não é detalhe de contabilidade: é a diferença entre o contato ouvir um
// silêncio de três segundos e ouvir a ligação cair para receber outra logo depois.
func TestReconnectWithinGraceResumesSameCall(t *testing.T) {
	withShortGrace(t, time.Hour)

	registry := GetSoftphoneRegistry()
	const instanceID = "inst_grace_resume"

	session := registry.open(instanceID, agentIdentity{ID: "op-1"})
	defer registry.close(session, closeReasonClientClosed)
	session.setConductingCall("call_1")
	bridge := session.Bridge()

	var ended bool
	beginGrace(session, func() { ended = true })

	resumed := registry.resume(instanceID, "op-1")

	if resumed != session {
		t.Fatal("a reconexão criou uma sessão nova; a chamada e a ponte teriam sido perdidas")
	}
	if got := resumed.State(); got != sessionStateConnected {
		t.Errorf("estado = %v, esperado %v", got, sessionStateConnected)
	}
	if got := resumed.ConductingCall(); got != "call_1" {
		t.Errorf("chamada = %q, esperado \"call_1\" — mesmo identificador (FR-038)", got)
	}
	if resumed.Bridge() != bridge {
		t.Error("a ponte de áudio foi trocada; a chamada perderia a fonte de áudio")
	}
	if !resumed.GraceUntil().IsZero() {
		t.Error("o prazo da graça não foi limpo ao retomar")
	}
	if ended {
		t.Error("a chamada foi encerrada apesar da reconexão dentro do prazo")
	}
}

// FR-039 e US8-AS3: esgotado o prazo, a chamada termina e a linha é liberada.
func TestGraceExpiryEndsTheCall(t *testing.T) {
	withShortGrace(t, 20*time.Millisecond)

	registry := GetSoftphoneRegistry()
	const instanceID = "inst_grace_expire"

	session := registry.open(instanceID, agentIdentity{ID: "op-1"})
	session.setConductingCall("call_1")

	ended := make(chan struct{})
	beginGrace(session, func() { close(ended) })

	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("o prazo venceu sem encerrar a chamada (FR-039)")
	}

	if got := session.State(); got != sessionStateClosed {
		t.Errorf("estado = %v, esperado %v", got, sessionStateClosed)
	}
	if got := session.CloseReason(); got != closeReasonGraceExpired {
		t.Errorf("motivo = %q, esperado %q", got, closeReasonGraceExpired)
	}
	if registry.session(instanceID, "op-1") != nil {
		t.Error("a sessão permaneceu no registro após o vencimento")
	}
}

// FR-041: o contato desligar durante a reconexão registra encerramento **pelo contato**, e
// não falha. O registro precisa refletir quem de fato terminou a ligação — atribuir a queda
// ao sistema quando foi o contato que desligou distorce qualquer análise de atendimento.
func TestContactHangupDuringGraceCancelsTheTimer(t *testing.T) {
	withShortGrace(t, 30*time.Millisecond)

	registry := GetSoftphoneRegistry()
	const instanceID = "inst_grace_contact"

	session := registry.open(instanceID, agentIdentity{ID: "op-1"})
	defer registry.close(session, closeReasonClientClosed)
	session.setConductingCall("call_1")

	expired := make(chan struct{}, 1)
	beginGrace(session, func() { expired <- struct{}{} })

	// O contato desliga: a chamada acaba pelo caminho normal, com o desfecho dele, e a
	// sessão deixa de conduzir chamada alguma.
	detachAgentFromCall(instanceID, "call_1")
	cancelGrace(session)

	select {
	case <-expired:
		t.Fatal("o encerramento por falha disparou mesmo com a chamada já encerrada pelo contato (FR-041)")
	case <-time.After(80 * time.Millisecond):
	}
}

// FR-042 e US8-AS5: reconectar **depois** do prazo devolve uma sessão ociosa, e nenhuma
// tentativa de retomada. A chamada anterior acabou, e insistir nela reconectaria o atendente
// a uma conversa que o contato já abandonou.
func TestReconnectAfterGraceStartsFresh(t *testing.T) {
	withShortGrace(t, 10*time.Millisecond)

	registry := GetSoftphoneRegistry()
	const instanceID = "inst_grace_late"

	session := registry.open(instanceID, agentIdentity{ID: "op-1"})
	session.setConductingCall("call_1")
	beginGrace(session, func() {})

	time.Sleep(60 * time.Millisecond)

	if resumed := registry.resume(instanceID, "op-1"); resumed != nil {
		t.Fatal("houve retomada após o prazo vencido; a chamada anterior já não existe (FR-042)")
	}

	fresh := registry.open(instanceID, agentIdentity{ID: "op-1"})
	defer registry.close(fresh, closeReasonClientClosed)

	if got := fresh.ConductingCall(); got != "" {
		t.Errorf("sessão nova conduz %q; deveria nascer ociosa", got)
	}
	if fresh == session {
		t.Error("a sessão vencida foi reaproveitada")
	}
}

// Uma sessão que não conduz chamada alguma não entra em graça: não há o que preservar, e
// mantê-la no registro faria a linha aparecer ocupada por um atendente que já foi embora.
func TestIdleSessionDoesNotEnterGrace(t *testing.T) {
	withShortGrace(t, time.Hour)

	registry := GetSoftphoneRegistry()
	const instanceID = "inst_grace_idle"

	session := registry.open(instanceID, agentIdentity{ID: "op-1"})

	beginGrace(session, func() {})

	if got := session.State(); got == sessionStateReconnecting {
		t.Error("sessão ociosa entrou em graça; não há chamada a preservar")
	}
	if registry.session(instanceID, "op-1") != nil {
		t.Error("sessão ociosa permaneceu no registro após a queda")
	}
}

// A tabela de desfechos precisa mapear o vencimento da graça para falha (FR-039).
func TestGraceExpiryReasonMapsToFailed(t *testing.T) {
	outcome, mapped := resolveCallOutcome(callEndReasonAgentLost)

	if !mapped {
		t.Fatalf("o motivo %q não está na tabela de desfechos", callEndReasonAgentLost)
	}
	if outcome != CallOutcomeFailed {
		t.Errorf("desfecho = %v, esperado %v", outcome, CallOutcomeFailed)
	}
}
