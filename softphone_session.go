package main

import (
	"sync"
	"time"
)

// Registro das sessões de softphone (feature 021, research §R9).
//
// Estado vivo, em memória, no mesmo processo que arbitra a vaga da instância. Não vai para o
// banco: a spec é explícita em que a sessão "existe apenas enquanto o atendente está
// conectado; não é histórico". Uma tabela sobreviveria ao processo que a sessão não
// sobrevive, e passaria a mentir a cada reinício.
//
// É deste mapa que saem as três publicações da feature — disponibilidade da linha (FR-033),
// leque da chamada entrante (FR-021) e estado da chamada (FR-013) — e é por ele estar no
// mesmo processo do `callRegistry` que nenhuma delas precisa de barramento.

// softphoneGracePeriod é a janela em que a chamada com o contato sobrevive à queda do
// atendente (FR-037).
//
// Quinze segundos: prazo suficiente para uma troca de rede, e curto o bastante para não
// deixar o contato ouvindo silêncio por tempo constrangedor. É decisão de produto revisável,
// e não restrição técnica — está registrada como premissa na spec.
//
// É `var` e não `const` para que os testes possam encurtá-la. A alternativa — esperar 15
// segundos reais por caso — deixaria a suíte lenta a ponto de ninguém rodá-la.
var softphoneGracePeriod = 15 * time.Second

type sessionState int

const (
	sessionStateConnected sessionState = iota
	sessionStateReconnecting
	sessionStateClosed
)

func (s sessionState) String() string {
	switch s {
	case sessionStateConnected:
		return "CONNECTED"
	case sessionStateReconnecting:
		return "RECONNECTING"
	case sessionStateClosed:
		return "CLOSED"
	}
	return "UNKNOWN"
}

// Motivos de encerramento. Chegam ao atendente no quadro `session.closed`, então cada um
// precisa dizer algo que ele possa agir a respeito.
const (
	// closeReasonSuperseded: o mesmo atendente abriu sessão em outro lugar (FR-011).
	closeReasonSuperseded = "SUPERSEDED"
	// closeReasonTokenInvalid: credencial recusada na abertura ou na renovação.
	closeReasonTokenInvalid = "TOKEN_INVALID"
	// closeReasonGraceExpired: o período de graça esgotou sem reconexão (FR-039).
	closeReasonGraceExpired = "GRACE_EXPIRED"
	// closeReasonClientClosed: o navegador fechou o socket.
	closeReasonClientClosed = "CLIENT_CLOSED"
	// closeReasonInstanceDisconnected: a instância perdeu a sessão do WhatsApp (FR-046).
	closeReasonInstanceDisconnected = "INSTANCE_DISCONNECTED"
	// closeReasonServerShutdown: o servidor de instância está encerrando.
	closeReasonServerShutdown = "SERVER_SHUTDOWN"
)

// agentSession é a presença de um atendente conectado a uma instância.
type agentSession struct {
	instanceID string
	agent      agentIdentity
	openedAt   time.Time

	mu          sync.Mutex
	state       sessionState
	closeReason string
	graceUntil  time.Time
	// callID é a chamada que esta sessão conduz, vazio quando ociosa. É o que permite dizer
	// aos demais atendentes quem está ocupando a linha (FR-034).
	callID string

	// send entrega um quadro à conexão. Injetado pelo WebSocket; nulo em teste, onde o que
	// importa é a contabilidade do registro e não o transporte.
	send func(frame any)

	// bridge é a ponte de áudio da sessão. Criada na abertura e **estável** enquanto a
	// sessão viver: é o que permite reconectar dentro do período de graça reapontando a
	// mídia sem que a chamada perceba (research §R4, FR-038).
	bridge *liveAudioBridge

	// media é a sessão WebRTC corrente. Esta, sim, é substituída a cada reconexão.
	media *softphoneMedia

	// graceTimer encerra a chamada se o atendente não voltar a tempo (FR-039).
	graceTimer *time.Timer
}

// State devolve o estado corrente sob o lock da sessão.
func (s *agentSession) State() sessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// CloseReason devolve o motivo do encerramento, ou vazio se a sessão ainda vive.
func (s *agentSession) CloseReason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeReason
}

// Agent devolve a identidade do atendente desta sessão.
func (s *agentSession) Agent() agentIdentity {
	return s.agent
}

// GraceUntil devolve o instante em que o período de graça expira, zero fora dele.
func (s *agentSession) GraceUntil() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.graceUntil
}

// markClosed encerra a sessão preservando o primeiro motivo.
//
// Preservar importa: uma sessão substituída (SUPERSEDED) costuma receber um close tardio do
// socket antigo (CLIENT_CLOSED) quando o navegador finalmente percebe a queda. Sobrescrever
// apagaria a razão que o atendente precisa ver — "sua sessão foi assumida em outro lugar" —
// e a trocaria por uma que não explica nada.
func (s *agentSession) markClosed(reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == sessionStateClosed {
		return false
	}
	s.state = sessionStateClosed
	s.closeReason = reason
	s.graceUntil = time.Time{}
	return true
}

// enterGrace coloca a sessão em reconexão até o instante informado (FR-037).
func (s *agentSession) enterGrace(until time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != sessionStateConnected {
		return false
	}
	s.state = sessionStateReconnecting
	s.graceUntil = until
	return true
}

// resume traz a sessão de volta da reconexão (FR-038).
func (s *agentSession) resume() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != sessionStateReconnecting {
		return false
	}
	s.state = sessionStateConnected
	s.graceUntil = time.Time{}
	return true
}

// softphoneRegistry guarda as sessões vivas, indexadas por instância e por atendente.
//
// A chave é o par `(instanceID, agentID)`, e não o `agentID` sozinho: o identificador é
// escolhido livremente pelo cliente, e nada impede que dois clientes distintos usem "op-1".
type softphoneRegistry struct {
	mu      sync.Mutex
	byAgent map[string]map[string]*agentSession
}

func newSoftphoneRegistry() *softphoneRegistry {
	return &softphoneRegistry{byAgent: make(map[string]map[string]*agentSession)}
}

var softphoneRegistryInstance = newSoftphoneRegistry()

// GetSoftphoneRegistry devolve o registro do processo.
func GetSoftphoneRegistry() *softphoneRegistry { return softphoneRegistryInstance }

// open abre uma sessão, encerrando a anterior do mesmo atendente (FR-011).
//
// A regra parece cosmética e não é: ela resolve de uma vez os três casos que a spec levanta
// como edge cases separados — o CRM aberto em duas abas, em dois computadores, e a
// credencial usada de dois lugares. Sem ela, duas sessões do mesmo atendente disputariam a
// mesma chamada e a ponte de áudio seria reapontada por quem chegasse por último, em
// silêncio.
func (r *softphoneRegistry) open(instanceID string, agent agentIdentity) *agentSession {
	session := &agentSession{
		instanceID: instanceID,
		agent:      agent,
		openedAt:   time.Now(),
		state:      sessionStateConnected,
		bridge:     newLiveAudioBridge(),
	}

	r.mu.Lock()
	agents, ok := r.byAgent[instanceID]
	if !ok {
		agents = make(map[string]*agentSession)
		r.byAgent[instanceID] = agents
	}
	previous := agents[agent.ID]
	agents[agent.ID] = session
	r.mu.Unlock()

	// O encerramento da anterior acontece fora do lock do registro: notificar o socket
	// antigo pode bloquear, e segurar o lock do registro enquanto isso trava toda a
	// instância — inclusive a publicação de disponibilidade da linha.
	if previous != nil && previous.markClosed(closeReasonSuperseded) {
		previous.notify(map[string]any{
			"t": "session.closed",
			"d": map[string]any{"reason": closeReasonSuperseded},
		})
	}

	return session
}

// close encerra a sessão e a remove do registro.
//
// A remoção é condicionada a a sessão ainda ser a vigente para aquele atendente. O caso
// acontece de verdade: o socket antigo detecta a queda depois que o novo já abriu, e chama
// close com uma referência obsoleta. Sem a condição, o atendente que acabou de reconectar
// seria expulso do registro pela morte do socket anterior — e pararia de receber chamadas
// entrantes sem qualquer sinal de que isso aconteceu.
func (r *softphoneRegistry) close(session *agentSession, reason string) {
	if session == nil {
		return
	}
	session.markClosed(reason)

	r.mu.Lock()
	defer r.mu.Unlock()
	agents, ok := r.byAgent[session.instanceID]
	if !ok {
		return
	}
	if current, ok := agents[session.agent.ID]; ok && current == session {
		delete(agents, session.agent.ID)
	}
	if len(agents) == 0 {
		delete(r.byAgent, session.instanceID)
	}
}

// sessions devolve as sessões vivas de uma instância.
//
// Uma cópia, e não o mapa: quem itera para publicar um quadro não pode segurar o lock do
// registro enquanto escreve em N sockets.
func (r *softphoneRegistry) sessions(instanceID string) []*agentSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	agents := r.byAgent[instanceID]
	if len(agents) == 0 {
		return nil
	}
	out := make([]*agentSession, 0, len(agents))
	for _, s := range agents {
		out = append(out, s)
	}
	return out
}

// session devolve a sessão de um atendente específico, se houver.
func (r *softphoneRegistry) session(instanceID, agentID string) *agentSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byAgent[instanceID][agentID]
}

// broadcast publica um quadro a todas as sessões vivas de uma instância.
func (r *softphoneRegistry) broadcast(instanceID string, frame any) {
	for _, session := range r.sessions(instanceID) {
		session.notify(frame)
	}
}

// closeInstance encerra todas as sessões de uma instância — usado quando a instância perde a
// sessão do WhatsApp ou o servidor está encerrando (FR-046).
func (r *softphoneRegistry) closeInstance(instanceID, reason string) {
	for _, session := range r.sessions(instanceID) {
		if session.markClosed(reason) {
			session.notify(map[string]any{
				"t": "session.closed",
				"d": map[string]any{"reason": reason},
			})
		}
		r.close(session, reason)
	}
}

// notify entrega um quadro à conexão da sessão, se houver uma.
func (s *agentSession) notify(frame any) {
	s.mu.Lock()
	send := s.send
	s.mu.Unlock()
	if send != nil {
		send(frame)
	}
}

// attach liga a sessão a uma conexão. Trocável, para que a reconexão dentro do período de
// graça reaproveite a mesma sessão (FR-038).
func (s *agentSession) attach(send func(frame any)) {
	s.mu.Lock()
	s.send = send
	s.mu.Unlock()
}

// lineStatePayload monta a indicação de disponibilidade da linha (FR-033, FR-034).
//
// Lê o `callRegistry`, que é a autoridade sobre a vaga: assim uma chamada iniciada por API,
// fora do softphone, também aparece como ocupada — que é exatamente o que US5-AS6 exige.
//
// `agent` é **omitido**, e não nulo, quando a chamada não tem autoria conhecida. A diferença
// importa: ausente diz "não houve atendente", e é o caso das chamadas por API.
func lineStatePayload(instanceID string) map[string]any {
	current := GetCallRegistry().current(instanceID)
	if current == nil || !current.occupies() {
		return map[string]any{"busy": false}
	}

	payload := map[string]any{"busy": true, "callId": current.CallID}
	if session := softphoneSessionConducting(instanceID, current.CallID); session != nil {
		payload["agent"] = softphoneAgentPayload(session.agent)
	}
	return payload
}

// softphoneSessionConducting devolve a sessão do atendente que conduz a chamada informada,
// ou nil quando ela não foi conduzida por nenhum — o caso das chamadas originadas por API.
func softphoneSessionConducting(instanceID, callID string) *agentSession {
	for _, session := range GetSoftphoneRegistry().sessions(instanceID) {
		if session.ConductingCall() == callID {
			return session
		}
	}
	return nil
}

// ConductingCall devolve o identificador da chamada que esta sessão conduz, ou vazio.
func (s *agentSession) ConductingCall() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callID
}

// setConductingCall registra qual chamada esta sessão conduz. Vazio a desassocia.
func (s *agentSession) setConductingCall(callID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callID = callID
}

// Bridge devolve a ponte de áudio estável da sessão.
func (s *agentSession) Bridge() *liveAudioBridge {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bridge
}

// setMedia troca a sessão WebRTC, encerrando a anterior.
//
// É esta troca — e só ela — que a reconexão dentro do período de graça exige. A ponte, a
// chamada, o Player e o gravador seguem intocados (FR-038).
func (s *agentSession) setMedia(m *softphoneMedia) {
	s.mu.Lock()
	previous := s.media
	s.media = m
	s.mu.Unlock()

	// Fechar a anterior **antes** de armar a nova, e nesta ordem: `Close` desarma o caminho
	// de volta da ponte, então armar primeiro seria armar para ser desarmado em seguida.
	// Concentrar as duas coisas aqui é o que torna a ordem verificável — espalhadas entre o
	// construtor da mídia e este método, elas se desfaziam mutuamente em silêncio.
	if previous != nil {
		previous.Close()
	}
	if m != nil && s.bridge != nil {
		s.bridge.SetPeerSink(m.sendToBrowser)
	}
}

// closeMediaOnly encerra a sessão WebRTC e **preserva** a ponte de áudio.
//
// A distinção é o coração de FR-038. A mídia pertence à conexão que caiu e será renegociada;
// a ponte pertence à sessão, é a fonte de áudio da chamada em curso, e fechá-la deixaria o
// contato ouvindo silêncio até o fim mesmo que o atendente voltasse.
func (s *agentSession) closeMediaOnly() {
	s.mu.Lock()
	m, bridge := s.media, s.bridge
	s.media = nil
	s.mu.Unlock()

	if m != nil {
		m.Close()
	}
	// Desarmar é responsabilidade de quem é dono da ponte, e é aqui — não no `Close` da
	// mídia, que não tem como saber se a ponte ainda aponta para ela. Sem destino vivo, o
	// áudio do contato é descartado até a renegociação, que é o que FR-037 descreve.
	if bridge != nil {
		bridge.SetPeerSink(nil)
	}
}

// closeMedia encerra a mídia e a ponte. Chamado quando a sessão morre de vez.
func (s *agentSession) closeMedia() {
	s.mu.Lock()
	m, bridge := s.media, s.bridge
	s.media = nil
	s.mu.Unlock()

	if m != nil {
		m.Close()
	}
	if bridge != nil {
		_ = bridge.Close()
	}
}

// setGraceTimer guarda o temporizador do período de graça.
func (s *agentSession) setGraceTimer(timer *time.Timer) {
	s.mu.Lock()
	previous := s.graceTimer
	s.graceTimer = timer
	s.mu.Unlock()

	if previous != nil {
		previous.Stop()
	}
}

// stopGraceTimer desarma o temporizador, se houver.
func (s *agentSession) stopGraceTimer() {
	s.mu.Lock()
	timer := s.graceTimer
	s.graceTimer = nil
	s.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
}

// resume devolve a sessão em período de graça de um atendente, retomando-a (FR-038).
//
// Devolve nil quando não há sessão em graça — o atendente reconectou depois do prazo, ou
// nunca esteve em uma. Nesse caso o chamador abre uma sessão nova, ociosa, e o componente
// informa que a chamada anterior caiu (FR-042).
//
// **Retomar em vez de abrir** é o que preserva a ponte de áudio e o identificador da chamada.
// Abrir uma sessão nova daria ao atendente um objeto novo, com uma ponte nova, e a chamada em
// curso ficaria sem fonte de áudio — o contato ouviria silêncio até o fim.
func (r *softphoneRegistry) resume(instanceID, agentID string) *agentSession {
	r.mu.Lock()
	session := r.byAgent[instanceID][agentID]
	r.mu.Unlock()

	if session == nil || session.State() != sessionStateReconnecting {
		return nil
	}

	session.stopGraceTimer()
	if !session.resume() {
		return nil
	}
	return session
}
