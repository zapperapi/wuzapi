package main

import (
	"sync"
	"sync/atomic"
	"testing"
)

// Disponibilidade da linha (US5, FR-033 a FR-036).
//
// A instância conduz uma chamada por vez, e o softphone multiplica o número de pessoas que
// disputam essa única linha. Sem visibilidade, cada tentativa vira um erro na cara do
// atendente; com ela, a limitação vira informação de operação.
//
// A fonte é o `callRegistry`, e não um estado paralelo — é o que faz uma chamada iniciada
// **por API**, fora do softphone, também aparecer como ocupada (US5-AS6).

// SC-008: diante de pedidos concorrentes na mesma instância, exatamente um é aceito.
//
// A garantia é o test-and-set sob um único mutex, antes de qualquer trabalho de rede. Não há
// lock distribuído porque não é preciso: toda chamada da instância passa por este processo.
func TestCallRegistryClaimGrantsExactlyOne(t *testing.T) {
	const contenders = 64
	r := &callRegistry{calls: make(map[string]*liveCall)}

	var granted atomic.Int32
	var refusals atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, _, err := r.claim("inst_race", CallDirectionBusinessInitiated, "5511999999999", false); err == nil {
				granted.Add(1)
				return
			}
			refusals.Add(1)
		}()
	}

	close(start)
	wg.Wait()

	if got := granted.Load(); got != 1 {
		t.Errorf("concessões = %d, esperado exatamente 1 (SC-008)", got)
	}
	if got := refusals.Load(); got != contenders-1 {
		t.Errorf("recusas = %d, esperado %d", got, contenders-1)
	}
}

// FR-035: a recusa informa QUAL chamada ocupa a linha — depois que ela existe.
//
// A ressalva não é preguiça de teste, é um limite do mundo: entre reivindicar a vaga e
// receber o identificador do WhatsApp existe uma ida e volta de rede, e nesse intervalo a
// chamada ainda não tem identificador algum para informar. Quem for recusado ali recebe
// `CALL_IN_PROGRESS` sem detalhe — degradação já prevista no `translateWuzapiCallError` do
// manager, que omite o `detail` quando ele vem vazio.
//
// A janela coincide com o tempo de discagem, que é justamente quando um segundo atendente
// tem mais chance de clicar. Fica registrado como limitação conhecida, e não como defeito a
// corrigir: nenhum desenho poderia informar um identificador que ainda não foi emitido.
func TestCallRegistryRefusalNamesTheCallInProgress(t *testing.T) {
	r := &callRegistry{calls: make(map[string]*liveCall)}

	if _, _, err := r.claim("inst_busy", CallDirectionBusinessInitiated, "5511999999999", false); err != nil {
		t.Fatalf("claim() inicial = %v", err)
	}
	r.bind("inst_busy", "call_em_curso", nil)

	_, busyWith, err := r.claim("inst_busy", CallDirectionBusinessInitiated, "5511888888888", false)
	if err == nil {
		t.Fatal("a segunda reivindicação deveria ter sido recusada")
	}
	if busyWith != "call_em_curso" {
		t.Errorf("callId informado = %q, esperado \"call_em_curso\"", busyWith)
	}
}

// FR-033 e US5-AS2: ocupar a linha publica a mudança a todos os componentes conectados.
func TestLineUpdatePublishedOnClaimAndRelease(t *testing.T) {
	registry := GetSoftphoneRegistry()
	const instanceID = "inst_line_pub"

	var mu sync.Mutex
	var updates []map[string]any

	session := registry.open(instanceID, agentIdentity{ID: "op-1"})
	defer registry.close(session, closeReasonClientClosed)
	session.attach(func(frame any) {
		m := asMap(frame)
		if m["t"] == "line.update" {
			mu.Lock()
			updates = append(updates, asMap(m["d"]))
			mu.Unlock()
		}
	})

	calls := GetCallRegistry()
	lc, _, err := calls.claim(instanceID, CallDirectionBusinessInitiated, "5511999999999", false)
	if err != nil {
		t.Fatalf("claim() = %v", err)
	}
	// `bind` publica a ocupação por conta própria — é onde o callID passa a existir.
	calls.bind(instanceID, "call_1", nil)

	// A liberação é publicada por quem encerra a chamada (`callEngine.finish`), depois de a
	// vaga já estar livre. Aqui o encerramento é simulado, então a publicação é explícita.
	calls.release(instanceID)
	publishLineState(instanceID)
	_ = lc

	mu.Lock()
	defer mu.Unlock()
	if len(updates) != 2 {
		t.Fatalf("publicações = %d, esperado 2 (ocupar e liberar)", len(updates))
	}
	if busy, _ := updates[0]["busy"].(bool); !busy {
		t.Error("primeira publicação deveria indicar linha ocupada")
	}
	if busy, _ := updates[1]["busy"].(bool); busy {
		t.Error("segunda publicação deveria indicar linha disponível")
	}
}

// US5-AS6: uma chamada originada **por API**, fora do softphone, também ocupa a linha.
//
// Sai de graça porque a fonte é o `callRegistry`: toda chamada passa pelo mesmo `claim`,
// venha de onde vier. Um estado paralelo mantido só pelo softphone perderia este caso.
func TestLineStateReflectsApiInitiatedCalls(t *testing.T) {
	const instanceID = "inst_line_api"
	calls := GetCallRegistry()

	if payload := lineStatePayload(instanceID); payload["busy"] != false {
		t.Fatalf("linha inicial = %v, esperado livre", payload["busy"])
	}

	// Nenhuma sessão de softphone envolvida: é o caminho da 020.
	if _, _, err := calls.claim(instanceID, CallDirectionBusinessInitiated, "5511999999999", false); err != nil {
		t.Fatalf("claim() = %v", err)
	}
	calls.bind(instanceID, "call_api", nil)
	defer calls.release(instanceID)

	payload := lineStatePayload(instanceID)
	if payload["busy"] != true {
		t.Error("linha deveria estar ocupada por uma chamada iniciada por API")
	}
	if payload["callId"] != "call_api" {
		t.Errorf("callId = %v, esperado \"call_api\"", payload["callId"])
	}
	// FR-054: chamada por API não tem autoria. **Ausente**, e não nula.
	if _, present := payload["agent"]; present {
		t.Error("chamada por API não deveria trazer autoria")
	}
}

// FR-034 e US5-AS3: com autoria conhecida, a indicação diz quem está na linha.
func TestLineStateNamesTheConductingAgent(t *testing.T) {
	const instanceID = "inst_line_agent"
	registry := GetSoftphoneRegistry()
	calls := GetCallRegistry()

	session := registry.open(instanceID, agentIdentity{ID: "op-1183", DisplayName: "Ana"})
	defer registry.close(session, closeReasonClientClosed)

	if _, _, err := calls.claim(instanceID, CallDirectionBusinessInitiated, "5511999999999", false); err != nil {
		t.Fatalf("claim() = %v", err)
	}
	calls.bind(instanceID, "call_ana", nil)
	defer calls.release(instanceID)
	session.setConductingCall("call_ana")

	payload := lineStatePayload(instanceID)
	agent := asMap(payload["agent"])
	if agent == nil {
		t.Fatal("autoria ausente; esperado o atendente que conduz a chamada")
	}
	if agent["id"] != "op-1183" {
		t.Errorf("id = %v, esperado \"op-1183\"", agent["id"])
	}
	if agent["displayName"] != "Ana" {
		t.Errorf("displayName = %v, esperado \"Ana\"", agent["displayName"])
	}
}

// Publicar sem nenhum componente conectado não pode falhar nem custar nada: é o estado
// normal de uma instância que usa só a API.
func TestPublishLineStateWithoutAgentsIsHarmless(t *testing.T) {
	publishLineState("inst_line_vazia")
}
