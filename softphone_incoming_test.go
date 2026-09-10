package main

import (
	"sync"
	"sync/atomic"
	"testing"

	"wuzapi/internal/meowcaller"
)

// Leque e corrida da chamada entrante (US4, FR-021 a FR-025).
//
// O que torna esta story delicada não é o leque — publicar para N sessões é um `for`. É a
// corrida: vários atendentes veem a mesma chamada tocando e podem clicar em aceitar no mesmo
// instante. Exatamente um precisa conduzi-la, e os outros precisam receber uma mensagem de
// situação normal, não de erro.

// SC-009: exatamente um atendente conduz uma chamada entrante.
//
// A garantia não vem de coordenação entre atendentes — vem de `takePending` ser uma leitura
// destrutiva sob mutex. Quem chega depois encontra o mapa vazio, e isso é decidido em um
// único processo, sem lock distribuído.
func TestTakePendingGrantsExactlyOneWinner(t *testing.T) {
	const contenders = 64

	engine := &callEngine{
		instanceID: "inst_race",
		pending:    map[string]*meowcaller.Call{"call_1": nil},
	}
	// Um valor não-nil para distinguir "ganhou" de "não havia": o mapa guarda ponteiros, e
	// nil seria indistinguível da ausência.
	sentinel := &meowcaller.Call{}
	engine.pending["call_1"] = sentinel

	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if call := engine.takePending("call_1"); call != nil {
				winners.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if got := winners.Load(); got != 1 {
		t.Errorf("vencedores = %d, esperado exatamente 1 (SC-009)", got)
	}
	if len(engine.pending) != 0 {
		t.Errorf("oferta permaneceu pendente após ser tomada: %d entradas", len(engine.pending))
	}
}

// FR-021 e US4-AS2: a oferta é sinalizada a **todas** as sessões da instância.
func TestPublishIncomingReachesEveryAgent(t *testing.T) {
	registry := GetSoftphoneRegistry()
	const instanceID = "inst_fanout"

	var mu sync.Mutex
	received := map[string]int{}

	for _, agentID := range []string{"op-1", "op-2", "op-3"} {
		session := registry.open(instanceID, agentIdentity{ID: agentID})
		defer registry.close(session, closeReasonClientClosed)
		id := agentID
		session.attach(func(frame any) {
			if asMap(frame)["t"] == "call.incoming" {
				mu.Lock()
				received[id]++
				mu.Unlock()
			}
		})
	}

	publishIncomingCall(instanceID, "call_1", "5511999999999@s.whatsapp.net")

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 3 {
		t.Fatalf("atendentes sinalizados = %d, esperado 3", len(received))
	}
	for agentID, count := range received {
		if count != 1 {
			t.Errorf("%s recebeu %d sinalizações, esperado 1", agentID, count)
		}
	}
}

// FR-024 e US4-AS3, AS5, AS6: os três desfechos da sinalização param o toque em todos.
func TestPublishIncomingClearedStopsEveryAgent(t *testing.T) {
	reasons := []string{"ANSWERED_ELSEWHERE", "REJECTED", "ABANDONED"}

	for _, reason := range reasons {
		t.Run(reason, func(t *testing.T) {
			registry := GetSoftphoneRegistry()
			instanceID := "inst_cleared_" + reason

			var mu sync.Mutex
			var cleared []string

			for _, agentID := range []string{"op-1", "op-2"} {
				session := registry.open(instanceID, agentIdentity{ID: agentID})
				defer registry.close(session, closeReasonClientClosed)
				session.attach(func(frame any) {
					m := asMap(frame)
					if m["t"] == "call.incoming.cleared" {
						mu.Lock()
						cleared = append(cleared, asMap(m["d"])["reason"].(string))
						mu.Unlock()
					}
				})
			}

			publishIncomingCleared(instanceID, "call_1", reason)

			mu.Lock()
			defer mu.Unlock()
			if len(cleared) != 2 {
				t.Fatalf("componentes avisados = %d, esperado 2", len(cleared))
			}
			for _, got := range cleared {
				if got != reason {
					t.Errorf("motivo = %q, esperado %q", got, reason)
				}
			}
		})
	}
}

// FR-025 e US4-AS7: sem nenhum atendente conectado, o comportamento da `020` permanece.
//
// É a garantia de compatibilidade mais importante desta story: um cliente que consome
// chamadas entrantes por webhook não pode perceber que o softphone existe.
func TestPublishIncomingWithoutAgentsIsHarmless(t *testing.T) {
	// Instância sem sessão alguma: publicar não pode entrar em pânico nem bloquear.
	publishIncomingCall("inst_sem_atendentes", "call_1", "5511999999999@s.whatsapp.net")
	publishIncomingCleared("inst_sem_atendentes", "call_1", "ABANDONED")

	if sessions := GetSoftphoneRegistry().sessions("inst_sem_atendentes"); len(sessions) != 0 {
		t.Errorf("sessões = %d, esperado 0", len(sessions))
	}
}

// US4-AS4: quem perde a corrida precisa saber que a chamada **já foi atendida**, e não que
// ela nunca existiu. A diferença aparece na tela do atendente: "atendida por outro" é
// situação normal; "chamada não encontrada" parece defeito do sistema.
func TestIncomingOutcomeDistinguishesTakenFromUnknown(t *testing.T) {
	registry := GetCallRegistry()
	const instanceID = "inst_outcome"

	// Chamada desconhecida: nunca existiu.
	if outcome := incomingOfferOutcome(instanceID, "call_fantasma"); outcome != incomingOfferUnknown {
		t.Errorf("chamada desconhecida = %v, esperado %v", outcome, incomingOfferUnknown)
	}

	// Chamada que outro atendente adotou: a vaga está ocupada por ela.
	lc, _, err := registry.claim(instanceID, CallDirectionUserInitiated, "5511999999999", false)
	if err != nil {
		t.Fatalf("claim() = %v", err)
	}
	registry.bind(instanceID, "call_tomada", nil)
	defer registry.release(instanceID)
	_ = lc

	if outcome := incomingOfferOutcome(instanceID, "call_tomada"); outcome != incomingOfferTaken {
		t.Errorf("chamada já adotada = %v, esperado %v", outcome, incomingOfferTaken)
	}
}

/** asMap facilita a leitura dos quadros publicados nos testes. */
func asMap(value any) map[string]any {
	m, _ := value.(map[string]any)
	return m
}
