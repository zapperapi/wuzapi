package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// Feature 028 (T101): a linha da Cloud API é do atendente, e não da instância.

func newTestCloudCall(instanceID, agentID string) *cloudCall {
	return &cloudCall{InstanceID: instanceID, AgentID: agentID, state: CallStateRinging}
}

func TestCloudRegistryAllowsSeveralCallsPerInstance(t *testing.T) {
	r := newCloudCallRegistry(10)
	for _, agent := range []string{"op-1", "op-2", "op-3"} {
		if err := r.reserve(newTestCloudCall("inst_1", agent)); err != nil {
			t.Fatalf("reserve %s: %v", agent, err)
		}
	}
	if got := r.count("inst_1"); got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
}

func TestCloudRegistryRefusesSecondCallOfSameAgent(t *testing.T) {
	r := newCloudCallRegistry(10)
	if err := r.reserve(newTestCloudCall("inst_1", "op-1")); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	err := r.reserve(newTestCloudCall("inst_1", "op-1"))
	if !errors.Is(err, errCloudAgentInCall) {
		t.Fatalf("second reserve error = %v, want errCloudAgentInCall", err)
	}
	// O mesmo identificador de atendente em outra instância é outra pessoa.
	if err := r.reserve(newTestCloudCall("inst_2", "op-1")); err != nil {
		t.Fatalf("reserve on another instance: %v", err)
	}
}

func TestCloudRegistryEnforcesInstanceCeiling(t *testing.T) {
	r := newCloudCallRegistry(2)
	_ = r.reserve(newTestCloudCall("inst_1", "op-1"))
	_ = r.reserve(newTestCloudCall("inst_1", "op-2"))
	err := r.reserve(newTestCloudCall("inst_1", "op-3"))
	if !errors.Is(err, errCloudCallLimit) {
		t.Fatalf("error = %v, want errCloudCallLimit", err)
	}
}

func TestCloudRegistryReleaseFreesAgentAndSeat(t *testing.T) {
	r := newCloudCallRegistry(1)
	call := newTestCloudCall("inst_1", "op-1")
	if err := r.reserve(call); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := r.bindCallID("inst_1", call.LegID, "wacid.1"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if r.find("inst_1", "wacid.1") != call || r.find("inst_1", call.LegID) != call {
		t.Fatal("call must be found by callId and by legId")
	}

	r.release(call)

	if r.find("inst_1", "wacid.1") != nil || r.agentCall("inst_1", "op-1") != nil {
		t.Fatal("released call must not be found")
	}
	if err := r.reserve(newTestCloudCall("inst_1", "op-1")); err != nil {
		t.Fatalf("agent must be free after release: %v", err)
	}
}

func TestCloudRegistryLateReleaseKeepsNewerCall(t *testing.T) {
	r := newCloudCallRegistry(10)
	old := newTestCloudCall("inst_1", "op-1")
	_ = r.reserve(old)
	r.release(old)
	current := newTestCloudCall("inst_1", "op-1")
	_ = r.reserve(current)

	r.release(old)

	if r.agentCall("inst_1", "op-1") != current {
		t.Fatal("a late release must not evict the agent's current call")
	}
}

func TestCloudRegistryDoesNotLeakAcrossInstances(t *testing.T) {
	r := newCloudCallRegistry(10)
	call := newTestCloudCall("inst_1", "op-1")
	_ = r.reserve(call)
	if r.find("inst_2", call.LegID) != nil {
		t.Fatal("a leg of another instance must look like it never existed")
	}
}

func TestCloudRegistryConcurrentReserveOfSameAgent(t *testing.T) {
	r := newCloudCallRegistry(100)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.reserve(newTestCloudCall("inst_1", "op-1")) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins.Load())
	}
}

func TestCloudRegistryConcurrentCeiling(t *testing.T) {
	r := newCloudCallRegistry(5)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			call := newTestCloudCall("inst_1", "op-"+string(rune('A'+i)))
			if r.reserve(call) == nil {
				wins.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 5 {
		t.Fatalf("winners = %d, want 5", wins.Load())
	}
}

func TestCloudMaxCallsFromEnv(t *testing.T) {
	t.Setenv("SOFTPHONE_CLOUD_MAX_CALLS_PER_INSTANCE", "")
	if got := cloudMaxCallsFromEnv(); got != defaultCloudMaxCallsPerInstance {
		t.Fatalf("default = %d", got)
	}
	t.Setenv("SOFTPHONE_CLOUD_MAX_CALLS_PER_INSTANCE", "7")
	if got := cloudMaxCallsFromEnv(); got != 7 {
		t.Fatalf("configured = %d", got)
	}
	t.Setenv("SOFTPHONE_CLOUD_MAX_CALLS_PER_INSTANCE", "zero")
	if got := cloudMaxCallsFromEnv(); got != defaultCloudMaxCallsPerInstance {
		t.Fatalf("invalid falls back = %d", got)
	}
}
