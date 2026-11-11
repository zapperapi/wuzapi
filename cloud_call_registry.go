package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"sync"

	"github.com/rs/zerolog/log"
)

// Registro das ligações da Cloud API conduzidas pelo softphone (feature 028, US6, research R17).
//
// O `callRegistry` do `device` guarda uma ligação por instância, porque um aparelho de
// WhatsApp não carrega duas conversas ao mesmo tempo. A Cloud API não tem esse limite: o
// número atende várias ligações em paralelo. A regra de linha passa a ser por atendente
// (FR-028): cada atendente conduz no máximo uma ligação, e a instância conduz até o teto da
// plataforma.
//
// Vive em memória, no mesmo processo que hospeda as sessões dos atendentes, pelo mesmo
// motivo do `callRegistry`: a decisão de "esta vaga é sua" é exata sob um mutex local, e
// nada sobrevive a um reinício — a ligação também não sobrevive.

// defaultCloudMaxCallsPerInstance é o teto de ligações simultâneas pelo softphone por
// instância (decisão D3). Protege o servidor de mídia; o limite da Meta é maior.
const defaultCloudMaxCallsPerInstance = 50

var (
	// errCloudAgentInCall: o atendente já conduz uma ligação nesta instância.
	errCloudAgentInCall = errors.New("cloud call: agent already conducts a call")
	// errCloudCallLimit: a instância atingiu o teto de ligações simultâneas.
	errCloudCallLimit = errors.New("cloud call: concurrent call limit reached for this instance")
	// errCloudCallNotFound: nenhuma ligação com esse identificador nesta instância.
	errCloudCallNotFound = errors.New("cloud call: call not found for this instance")
)

// cloudCallRegistry guarda as ligações vivas por instância. Cada ligação é indexada pelo
// `legId`, que existe desde a reserva, e pelo `callId` da Meta, que só existe depois do
// `connect` na ligação feita.
type cloudCallRegistry struct {
	mu sync.Mutex
	// byLeg: instância → legId → ligação.
	byLeg map[string]map[string]*cloudCall
	// byCall: instância → callId da Meta → legId.
	byCall map[string]map[string]string
	// byAgent: instância → atendente → legId. É o que cumpre "uma por atendente".
	byAgent map[string]map[string]string

	maxPerInstance int
}

func newCloudCallRegistry(maxPerInstance int) *cloudCallRegistry {
	if maxPerInstance < 1 {
		maxPerInstance = defaultCloudMaxCallsPerInstance
	}
	return &cloudCallRegistry{
		byLeg:          make(map[string]map[string]*cloudCall),
		byCall:         make(map[string]map[string]string),
		byAgent:        make(map[string]map[string]string),
		maxPerInstance: maxPerInstance,
	}
}

var (
	cloudCallRegistryOnce     sync.Once
	cloudCallRegistryInstance *cloudCallRegistry
)

// GetCloudCallRegistry devolve o registro do processo, com o teto lido do ambiente.
func GetCloudCallRegistry() *cloudCallRegistry {
	cloudCallRegistryOnce.Do(func() {
		cloudCallRegistryInstance = newCloudCallRegistry(cloudMaxCallsFromEnv())
	})
	return cloudCallRegistryInstance
}

// cloudMaxCallsFromEnv lê `SOFTPHONE_CLOUD_MAX_CALLS_PER_INSTANCE`. Valor ausente ou inválido
// cai no padrão: um erro de digitação não pode zerar o teto e recusar toda ligação.
func cloudMaxCallsFromEnv() int {
	raw := os.Getenv("SOFTPHONE_CLOUD_MAX_CALLS_PER_INSTANCE")
	if raw == "" {
		return defaultCloudMaxCallsPerInstance
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		log.Warn().Str("variable", "SOFTPHONE_CLOUD_MAX_CALLS_PER_INSTANCE").Str("value", raw).
			Int("fallback", defaultCloudMaxCallsPerInstance).
			Msg("Invalid cloud call limit in environment, using default")
		return defaultCloudMaxCallsPerInstance
	}
	return value
}

// newLegID gera o identificador da perna de mídia. Aleatório: ele circula entre o manager e
// este servidor, e não pode ser adivinhado a partir de outro.
func newLegID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand não falha em sistema saudável; se falhar, nenhum identificador é
		// seguro, e a ligação não deve começar.
		panic("cloud call: crypto/rand unavailable: " + err.Error())
	}
	return "leg_" + hex.EncodeToString(buf)
}

// reserve registra a ligação de um atendente, ou recusa.
//
// A checagem e a escrita acontecem sob o mesmo lock: de N pedidos simultâneos do mesmo
// atendente, exatamente um sai com a vaga. A reserva vem antes de qualquer trabalho de mídia,
// pela mesma razão do `callRegistry.claim`.
func (r *cloudCallRegistry) reserve(call *cloudCall) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	instance := call.InstanceID
	if legID, ok := r.byAgent[instance][call.AgentID]; ok && legID != "" {
		return errCloudAgentInCall
	}
	if len(r.byLeg[instance]) >= r.maxPerInstance {
		return errCloudCallLimit
	}

	if call.LegID == "" {
		call.LegID = newLegID()
	}
	if r.byLeg[instance] == nil {
		r.byLeg[instance] = make(map[string]*cloudCall)
		r.byCall[instance] = make(map[string]string)
		r.byAgent[instance] = make(map[string]string)
	}
	r.byLeg[instance][call.LegID] = call
	r.byAgent[instance][call.AgentID] = call.LegID
	if callID := call.CallID(); callID != "" {
		r.byCall[instance][callID] = call.LegID
	}
	return nil
}

// bindCallID associa o `callId` da Meta a uma perna já reservada (ligação feita).
func (r *cloudCallRegistry) bindCallID(instanceID, legID, callID string) (*cloudCall, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	call := r.byLeg[instanceID][legID]
	if call == nil {
		return nil, errCloudCallNotFound
	}
	call.setCallID(callID)
	r.byCall[instanceID][callID] = legID
	return call, nil
}

// find devolve a ligação pelo `legId` ou pelo `callId` da Meta.
//
// A instância faz parte da busca, e não é um filtro aplicado depois: o identificador de outra
// instância responde igual a um que nunca existiu (Princípio II).
func (r *cloudCallRegistry) find(instanceID, id string) *cloudCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	if call := r.byLeg[instanceID][id]; call != nil {
		return call
	}
	if legID, ok := r.byCall[instanceID][id]; ok {
		return r.byLeg[instanceID][legID]
	}
	return nil
}

// agentCall devolve a ligação que o atendente conduz, se houver.
func (r *cloudCallRegistry) agentCall(instanceID, agentID string) *cloudCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	legID, ok := r.byAgent[instanceID][agentID]
	if !ok {
		return nil
	}
	return r.byLeg[instanceID][legID]
}

// count devolve quantas ligações a instância conduz.
func (r *cloudCallRegistry) count(instanceID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.byLeg[instanceID])
}

// release libera a vaga da ligação e do atendente.
//
// Só remove o que ainda pertence a esta ligação: uma liberação atrasada não pode apagar a
// vaga que o mesmo atendente já reservou para a ligação seguinte.
func (r *cloudCallRegistry) release(call *cloudCall) {
	if call == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	instance := call.InstanceID
	if current := r.byLeg[instance][call.LegID]; current != call {
		return
	}
	delete(r.byLeg[instance], call.LegID)
	if callID := call.CallID(); callID != "" && r.byCall[instance][callID] == call.LegID {
		delete(r.byCall[instance], callID)
	}
	if r.byAgent[instance][call.AgentID] == call.LegID {
		delete(r.byAgent[instance], call.AgentID)
	}
	if len(r.byLeg[instance]) == 0 {
		delete(r.byLeg, instance)
		delete(r.byCall, instance)
		delete(r.byAgent, instance)
	}
}

// drainInstance remove e devolve todas as ligações de uma instância.
func (r *cloudCallRegistry) drainInstance(instanceID string) []*cloudCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	calls := make([]*cloudCall, 0, len(r.byLeg[instanceID]))
	for _, call := range r.byLeg[instanceID] {
		calls = append(calls, call)
	}
	delete(r.byLeg, instanceID)
	delete(r.byCall, instanceID)
	delete(r.byAgent, instanceID)
	return calls
}
