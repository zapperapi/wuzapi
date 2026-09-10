package main

import (
	"testing"
)

// FR-011: para um mesmo atendente, apenas a sessão mais recente permanece ativa.
//
// A regra parece cosmética e não é. Ela resolve três casos que a spec levanta como edge
// cases distintos e que são o mesmo caso: o atendente que abre o CRM em duas abas, o que
// abre em dois computadores, e a credencial usada de dois lugares ao mesmo tempo. Sem ela,
// duas sessões do mesmo atendente disputariam a mesma chamada e a ponte de áudio seria
// reapontada por quem chegasse por último, silenciosamente.
func TestSoftphoneRegistryKeepsOnlyLatestSessionPerAgent(t *testing.T) {
	r := newSoftphoneRegistry()

	first := r.open("inst_A", agentIdentity{ID: "op-1", DisplayName: "Ana"})
	second := r.open("inst_A", agentIdentity{ID: "op-1", DisplayName: "Ana"})

	if first == second {
		t.Fatal("a segunda abertura deveria produzir uma sessão nova")
	}
	if got := first.State(); got != sessionStateClosed {
		t.Errorf("sessão anterior: estado = %v, esperado %v", got, sessionStateClosed)
	}
	if got := first.CloseReason(); got != closeReasonSuperseded {
		t.Errorf("sessão anterior: motivo = %q, esperado %q", got, closeReasonSuperseded)
	}
	if got := second.State(); got != sessionStateConnected {
		t.Errorf("sessão nova: estado = %v, esperado %v", got, sessionStateConnected)
	}
	if sessions := r.sessions("inst_A"); len(sessions) != 1 {
		t.Errorf("sessões ativas = %d, esperado 1", len(sessions))
	}
}

// Atendentes diferentes convivem: é o que torna o leque da chamada entrante (FR-021) e a
// disputa pela linha (FR-036) possíveis.
func TestSoftphoneRegistryKeepsDistinctAgents(t *testing.T) {
	r := newSoftphoneRegistry()

	a := r.open("inst_A", agentIdentity{ID: "op-1"})
	b := r.open("inst_A", agentIdentity{ID: "op-2"})

	if a.State() != sessionStateConnected || b.State() != sessionStateConnected {
		t.Fatal("as duas sessões deveriam permanecer conectadas")
	}
	if sessions := r.sessions("inst_A"); len(sessions) != 2 {
		t.Errorf("sessões ativas = %d, esperado 2", len(sessions))
	}
}

// O mesmo identificador de atendente em instâncias distintas são dois atendentes distintos.
// A chave é o par, e não o identificador: o cliente escolhe o identificador livremente e
// nada impede que dois clientes usem "op-1".
func TestSoftphoneRegistryScopesAgentsByInstance(t *testing.T) {
	r := newSoftphoneRegistry()

	a := r.open("inst_A", agentIdentity{ID: "op-1"})
	b := r.open("inst_B", agentIdentity{ID: "op-1"})

	if a.State() != sessionStateConnected {
		t.Error("a sessão da instância A não deveria ter sido encerrada pela da B")
	}
	if b.State() != sessionStateConnected {
		t.Error("a sessão da instância B deveria estar conectada")
	}
	if got := len(r.sessions("inst_A")); got != 1 {
		t.Errorf("sessões em inst_A = %d, esperado 1", got)
	}
	if got := len(r.sessions("inst_B")); got != 1 {
		t.Errorf("sessões em inst_B = %d, esperado 1", got)
	}
}

// Fechar remove do registro. Sem isto, o leque da entrante publicaria para sessões mortas e
// a linha apareceria ocupada para quem já foi embora.
func TestSoftphoneRegistryCloseRemovesSession(t *testing.T) {
	r := newSoftphoneRegistry()
	s := r.open("inst_A", agentIdentity{ID: "op-1"})

	r.close(s, closeReasonClientClosed)

	if got := s.State(); got != sessionStateClosed {
		t.Errorf("estado = %v, esperado %v", got, sessionStateClosed)
	}
	if got := s.CloseReason(); got != closeReasonClientClosed {
		t.Errorf("motivo = %q, esperado %q", got, closeReasonClientClosed)
	}
	if sessions := r.sessions("inst_A"); len(sessions) != 0 {
		t.Errorf("sessões ativas = %d, esperado 0", len(sessions))
	}
}

// Fechar uma sessão já substituída não pode derrubar a que a substituiu. O caso acontece de
// verdade: o socket antigo detecta a queda depois que o novo já abriu, e chama close com uma
// referência obsoleta.
func TestSoftphoneRegistryCloseOfSupersededSessionDoesNotEvictSuccessor(t *testing.T) {
	r := newSoftphoneRegistry()
	first := r.open("inst_A", agentIdentity{ID: "op-1"})
	second := r.open("inst_A", agentIdentity{ID: "op-1"})

	r.close(first, closeReasonClientClosed)

	if got := second.State(); got != sessionStateConnected {
		t.Errorf("sessão vigente: estado = %v, esperado %v", got, sessionStateConnected)
	}
	if sessions := r.sessions("inst_A"); len(sessions) != 1 {
		t.Fatalf("sessões ativas = %d, esperado 1", len(sessions))
	}
	// O motivo do fechamento da primeira permanece SUPERSEDED: foi o que de fato a
	// encerrou, e sobrescrevê-lo apagaria a razão que o atendente precisa ver.
	if got := first.CloseReason(); got != closeReasonSuperseded {
		t.Errorf("sessão anterior: motivo = %q, esperado %q", got, closeReasonSuperseded)
	}
}

// SC-012 e US3-AS4: a instância nunca fica presa a uma chamada que não existe mais.
//
// É a garantia que torna o softphone utilizável no segundo atendimento do dia. Toda saída
// precisa liberar a vaga — encerramento pelo atendente, pelo contato, ou falha — porque o
// custo de errar é a linha da empresa parar até alguém reiniciar o serviço.
func TestCallRegistrySeatIsFreeAfterEveryExit(t *testing.T) {
	exits := map[string]func(r *callRegistry, instanceID, callID string){
		"release":     func(r *callRegistry, id, _ string) { r.release(id) },
		"releaseCall": func(r *callRegistry, id, callID string) { r.releaseCall(id, callID) },
		"drain":       func(r *callRegistry, id, _ string) { r.drainInstance(id) },
	}

	for name, exit := range exits {
		t.Run(name, func(t *testing.T) {
			r := &callRegistry{calls: make(map[string]*liveCall)}

			lc, _, err := r.claim("inst_A", CallDirectionBusinessInitiated, "5511999999999", false)
			if err != nil {
				t.Fatalf("claim() inicial = %v", err)
			}
			r.bind("inst_A", "call_1", nil)

			// A vaga está ocupada: uma segunda tentativa precisa ser recusada.
			if _, busy, err := r.claim("inst_A", CallDirectionBusinessInitiated, "5511888888888", false); err == nil {
				t.Fatal("segunda reivindicação deveria ter sido recusada com a linha ocupada")
			} else if busy != lc.CallID {
				t.Errorf("recusa informou callId = %q, esperado %q", busy, lc.CallID)
			}

			exit(r, "inst_A", lc.CallID)

			// E, liberada, a próxima é aceita — que é o que US3-AS4 cobra.
			if _, _, err := r.claim("inst_A", CallDirectionBusinessInitiated, "5511888888888", false); err != nil {
				t.Fatalf("claim() após %s = %v, esperado aceitar", name, err)
			}
		})
	}
}

// A sessão do atendente é desassociada da chamada encerrada, mas **continua aberta**: ela
// serve o próximo atendimento. Confundir as duas coisas faria o atendente ter de recarregar
// a página entre uma ligação e outra.
func TestDetachAgentKeepsSessionOpen(t *testing.T) {
	registry := GetSoftphoneRegistry()
	session := registry.open("inst_detach", agentIdentity{ID: "op-1"})
	defer registry.close(session, closeReasonClientClosed)

	session.setConductingCall("call_1")
	detachAgentFromCall("inst_detach", "call_1")

	if got := session.ConductingCall(); got != "" {
		t.Errorf("ConductingCall() = %q, esperado vazio após o encerramento", got)
	}
	if got := session.State(); got != sessionStateConnected {
		t.Errorf("estado = %v, esperado %v — a sessão serve a próxima chamada", got, sessionStateConnected)
	}
}

// Desassociar uma chamada que não é a da sessão não pode desassociar a que é. Acontece
// quando o encerramento tardio de uma chamada anterior chega depois que a seguinte começou.
func TestDetachAgentIgnoresOtherCalls(t *testing.T) {
	registry := GetSoftphoneRegistry()
	session := registry.open("inst_detach2", agentIdentity{ID: "op-1"})
	defer registry.close(session, closeReasonClientClosed)

	session.setConductingCall("call_atual")
	detachAgentFromCall("inst_detach2", "call_anterior")

	if got := session.ConductingCall(); got != "call_atual" {
		t.Errorf("ConductingCall() = %q, esperado \"call_atual\"", got)
	}
}
