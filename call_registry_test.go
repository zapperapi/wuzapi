package main

import (
	"sync"
	"testing"
)

// newTestRegistry gives each test its own registry: the package-level one is
// process-wide, and sharing it between tests would let a leftover seat from one
// case decide the outcome of another.
func newTestRegistry() *callRegistry {
	return &callRegistry{calls: make(map[string]*liveCall)}
}

func TestClaimHoldsTheSeat(t *testing.T) {
	r := newTestRegistry()

	if _, _, err := r.claim("inst_1", CallDirectionBusinessInitiated, "peer", false); err != nil {
		t.Fatalf("first claim failed: %v", err)
	}
	r.bind("inst_1", "CALL-1", nil)

	_, busyWith, err := r.claim("inst_1", CallDirectionBusinessInitiated, "peer", false)
	if err != ErrCallInProgress {
		t.Fatalf("second claim err = %v, want ErrCallInProgress", err)
	}
	if busyWith != "CALL-1" {
		t.Fatalf("busyWith = %q, want the occupying call id", busyWith)
	}
}

// A ringing call occupies the instance just as much as an active one: the device
// is busy from the first ring, not from the answer (FR-023, US5-AS3).
func TestRingingCallOccupiesTheSeat(t *testing.T) {
	r := newTestRegistry()
	lc, _, _ := r.claim("inst_1", CallDirectionBusinessInitiated, "peer", false)

	if lc.State() != CallStateRinging {
		t.Fatalf("state = %q, want RINGING", lc.State())
	}
	if !lc.occupies() {
		t.Fatal("a ringing call must occupy the instance")
	}
}

// Releasing must make the instance immediately reusable -- this is what makes
// answering and placing calls repeatable (FR-020, US3-AS5).
func TestReleaseFreesTheSeatForANewCall(t *testing.T) {
	r := newTestRegistry()
	r.claim("inst_1", CallDirectionBusinessInitiated, "peer", false)
	r.bind("inst_1", "CALL-1", nil)

	r.release("inst_1")

	if _, _, err := r.claim("inst_1", CallDirectionUserInitiated, "peer", false); err != nil {
		t.Fatalf("claim after release failed: %v", err)
	}
}

// A late teardown from a finished call must not evict the call that replaced it,
// which would report the seat free while a conversation was live.
func TestReleaseCallOnlyReleasesItsOwnCall(t *testing.T) {
	r := newTestRegistry()
	r.claim("inst_1", CallDirectionBusinessInitiated, "peer", false)
	r.bind("inst_1", "CALL-2", nil)

	r.releaseCall("inst_1", "CALL-1") // teardown of the previous call

	if r.current("inst_1") == nil {
		t.Fatal("a stale teardown evicted the live call")
	}
}

// The seat is per instance, never per account (US5-AS5).
func TestSeatIsScopedToTheInstance(t *testing.T) {
	r := newTestRegistry()
	r.claim("inst_1", CallDirectionBusinessInitiated, "peer", false)

	if _, _, err := r.claim("inst_2", CallDirectionBusinessInitiated, "peer", false); err != nil {
		t.Fatalf("a second instance was blocked by the first: %v", err)
	}
}

// A call id belonging to another instance must be indistinguishable from one
// that never existed (FR-012, Princípio II).
func TestGetIsScopedToTheInstance(t *testing.T) {
	r := newTestRegistry()
	r.claim("inst_1", CallDirectionBusinessInitiated, "peer", false)
	r.bind("inst_1", "CALL-1", nil)

	if _, err := r.get("inst_2", "CALL-1"); err != ErrCallNotFound {
		t.Fatalf("cross-instance get err = %v, want ErrCallNotFound", err)
	}
	if _, err := r.get("inst_1", "NAO-EXISTE"); err != ErrCallNotFound {
		t.Fatalf("unknown call err = %v, want ErrCallNotFound", err)
	}
}

// SC-007: of N simultaneous requests for one instance, exactly one wins. This is
// a race, so a single pass proves nothing -- the loop is the test.
func TestConcurrentClaimsGrantExactlyOne(t *testing.T) {
	for round := 0; round < 200; round++ {
		r := newTestRegistry()

		const contenders = 16
		var granted int32
		var mu sync.Mutex
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(contenders)

		for i := 0; i < contenders; i++ {
			go func() {
				defer done.Done()
				start.Wait()
				if _, _, err := r.claim("inst_1", CallDirectionBusinessInitiated, "peer", false); err == nil {
					mu.Lock()
					granted++
					mu.Unlock()
				}
			}()
		}

		start.Done()
		done.Wait()

		if granted != 1 {
			t.Fatalf("round %d: %d claims granted, want exactly 1", round, granted)
		}
	}
}

// drainInstance is the lost-session path: it must end the call, hand it back for
// reporting, and leave the instance free (FR-022, SC-006).
func TestDrainInstanceEndsAndFrees(t *testing.T) {
	r := newTestRegistry()
	r.claim("inst_1", CallDirectionUserInitiated, "peer", false)
	r.bind("inst_1", "CALL-1", nil)

	drained := r.drainInstance("inst_1")
	if drained == nil || drained.CallID != "CALL-1" {
		t.Fatal("drainInstance did not return the call it ended")
	}
	if drained.State() != CallStateEnded {
		t.Fatalf("drained call state = %q, want ENDED", drained.State())
	}
	if r.current("inst_1") != nil {
		t.Fatal("instance still holds a seat after drain")
	}
	if r.drainInstance("inst_1") != nil {
		t.Fatal("draining an idle instance must return nothing")
	}
}
