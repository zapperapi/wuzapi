package main

import (
	"errors"
	"sync"
	"time"

	"wuzapi/internal/meowcaller"
)

// CallState is the lifecycle state of a call as this server sees it. It mirrors the
// CallState enum persisted by zapperapi-manager, so a value never has to be
// translated on the way out.
type CallState string

const (
	CallStateRinging CallState = "RINGING"
	CallStateActive  CallState = "ACTIVE"
	CallStateEnded   CallState = "ENDED"
)

// CallDirection says who placed the call.
type CallDirection string

const (
	CallDirectionUserInitiated     CallDirection = "USER_INITIATED"
	CallDirectionBusinessInitiated CallDirection = "BUSINESS_INITIATED"
)

// ErrCallInProgress is returned when an instance is asked for a call while it
// already has one. The seat is physical: a WhatsApp device does not carry two
// conversations at once (FR-023).
//
// Callers surface the occupying call's ID alongside it, so the customer's
// automation learns which call to end instead of finding out by trial and error
// (FR-024). Never let this error travel without that ID.
var ErrCallInProgress = errors.New("instance already has a call in progress")

// ErrCallNotFound is returned for a call ID this instance does not own. It is
// deliberately indistinguishable from "never existed": telling a caller that an ID
// belongs to somebody else would already be a cross-tenant leak (FR-012).
var ErrCallNotFound = errors.New("call not found for this instance")

// liveCall is one in-flight call. It exists only in memory, and only for as long as
// the process does: nothing survives a restart, by design (FR-022).
type liveCall struct {
	CallID    string
	Peer      string
	Direction CallDirection

	// Recording says whether the customer asked to record AND the quota granted it.
	// A call that was requested but not granted records nothing.
	Recording bool

	StartedAt     time.Time
	EstablishedAt time.Time

	// call is the meowcaller handle. It is nil for the window between the seat
	// being claimed and the offer reaching the wire -- claiming first is what makes
	// concurrent requests resolve to exactly one winner (FR-025).
	call *meowcaller.Call

	mu    sync.Mutex
	state CallState

	// player is the audio playing right now, if any. A call carries at most one:
	// a new request replaces the current one, never overlaps it (FR-018).
	player *meowcaller.Player
	// recorder captures both legs; nil when the call is not being recorded. A call
	// without one retains no conversation audio at all (FR-027).
	recorder *callRecorder

	// playerCleanup releases the temporary media file backing `player`.
	//
	// It exists because meowcaller's file sources STREAM: WAVFile keeps the file
	// open and reads it as the call consumes frames. Deleting the file when the
	// request returns would pull the audio out from under a playback still running.
	playerCleanup func()
}

// play starts a playback, replacing whatever was running (FR-018).
//
// cleanup releases the temporary media file and runs exactly once: when this
// playback is replaced, stopped, or finishes on its own.
func (c *liveCall) play(src meowcaller.AudioSource, cleanup func()) (time.Time, error) {
	c.mu.Lock()
	if c.call == nil {
		c.mu.Unlock()
		cleanup()
		return time.Time{}, errors.New("call has no media session")
	}
	c.stopPlaybackLocked()
	// Tee into the local track before the call consumes it, so the recording holds
	// what the contact actually heard (FR-028).
	if c.recorder != nil {
		src = c.recorder.WrapSource(src)
	}
	player := c.call.Play(src)
	c.player, c.playerCleanup = player, cleanup
	c.mu.Unlock()

	player.OnFinish(func() { c.playbackFinished(player) })
	return time.Now(), nil
}

// playbackFinished releases the media of a playback that ended on its own.
//
// The identity check matters: a replaced playback can report finishing after its
// successor started, and releasing then would delete the file the NEW audio is
// streaming from.
func (c *liveCall) playbackFinished(player *meowcaller.Player) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.player != player {
		return
	}
	c.player = nil
	if c.playerCleanup != nil {
		c.playerCleanup()
		c.playerCleanup = nil
	}
}

// stopPlayback halts any audio and releases its media.
func (c *liveCall) stopPlayback() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopPlaybackLocked()
}

// stopPlaybackLocked is stopPlayback for callers already holding c.mu.
//
// Stop() first, cleanup second: the source must be closed before the file it reads
// from is removed.
func (c *liveCall) stopPlaybackLocked() {
	if c.player != nil {
		c.player.Stop()
		c.player = nil
	}
	if c.playerCleanup != nil {
		c.playerCleanup()
		c.playerCleanup = nil
	}
}

// State reads the call's state under its own lock.
func (c *liveCall) State() CallState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *liveCall) setState(s CallState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = s
}

// end marks the call over and releases whatever media it was playing.
//
// Every exit path goes through here, so a temporary audio file can never outlive the
// call it was playing into. Idempotent.
func (c *liveCall) end() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = CallStateEnded
	c.stopPlaybackLocked()
}

// occupies reports whether this call holds the instance's seat. A ringing call
// counts: the device is busy from the first ring, not from the answer (FR-023).
func (c *liveCall) occupies() bool {
	switch c.State() {
	case CallStateRinging, CallStateActive:
		return true
	default:
		return false
	}
}

// callRegistry is the authority on "one call per instance".
//
// This lives here, in the instance server, rather than in zapperapi-manager,
// because this is the only process every call must pass through. The manager runs
// behind a load balancer with several replicas; a gate there would need a
// distributed lock and could still disagree with the device. A local mutex is exact
// by construction (research §R3).
type callRegistry struct {
	mu    sync.Mutex
	calls map[string]*liveCall // keyed by instance ID (wuzapi's userID)
}

var callRegistryInstance = &callRegistry{calls: make(map[string]*liveCall)}

// GetCallRegistry returns the process-wide registry.
func GetCallRegistry() *callRegistry { return callRegistryInstance }

// claim reserves the instance's seat for a new call, or reports who already holds it.
//
// This is the whole concurrency story of the feature: the check and the write happen
// under one lock, so of N simultaneous requests exactly one leaves with the seat
// (FR-025). Claim BEFORE any network work -- placing the offer first and reserving
// afterwards would let two offers reach WhatsApp before either was rejected.
//
// The returned call starts RINGING and its CallID is empty until bind fills it in.
func (r *callRegistry) claim(instanceID string, direction CallDirection, peer string, recording bool) (*liveCall, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing := r.calls[instanceID]; existing != nil {
		if existing.occupies() {
			return nil, existing.CallID, ErrCallInProgress
		}
		// A finished call left behind: the seat is free, the entry is stale.
		delete(r.calls, instanceID)
	}

	lc := &liveCall{
		Peer:      peer,
		Direction: direction,
		Recording: recording,
		StartedAt: time.Now(),
		state:     CallStateRinging,
	}
	r.calls[instanceID] = lc
	return lc, "", nil
}

// bind attaches the call ID and the meowcaller handle once the offer is on the wire.
//
// Separate from claim because the ID does not exist until WhatsApp has been asked.
// If the offer failed, callers must release instead -- never leave a seat held by a
// call that never happened.
func (r *callRegistry) bind(instanceID, callID string, call *meowcaller.Call) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if lc := r.calls[instanceID]; lc != nil {
		lc.CallID = callID
		lc.call = call
	}
}

// adopt registers an inbound call the platform is about to answer, claiming the seat
// for it. The call ID is already known here, because it arrived in the offer.
func (r *callRegistry) adopt(instanceID, callID, peer string, call *meowcaller.Call, recording bool) (*liveCall, string, error) {
	lc, busyWith, err := r.claim(instanceID, CallDirectionUserInitiated, peer, recording)
	if err != nil {
		return nil, busyWith, err
	}
	r.bind(instanceID, callID, call)
	return lc, "", nil
}

// get returns the instance's current call when the ID matches.
//
// The instance ID is part of the lookup, not a filter applied afterwards: a call ID
// belonging to another instance must be indistinguishable from one that never
// existed (FR-012, Princípio II).
func (r *callRegistry) get(instanceID, callID string) (*liveCall, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	lc := r.calls[instanceID]
	if lc == nil || lc.CallID != callID {
		return nil, ErrCallNotFound
	}
	return lc, nil
}

// current returns the instance's call, whatever its ID, or nil.
func (r *callRegistry) current(instanceID string) *liveCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[instanceID]
}

// release frees the instance's seat.
//
// Called on every exit path without exception -- command, peer hangup, signaling
// failure, lost session, failed offer. An instance must never be left holding a seat
// for a call that is over (FR-020, SC-006).
func (r *callRegistry) release(instanceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if lc := r.calls[instanceID]; lc != nil {
		lc.end()
		delete(r.calls, instanceID)
	}
}

// releaseCall frees the seat only if it is still held by this exact call.
//
// Guards against a late teardown from a previous call evicting the call that
// replaced it -- the seat would be reported free while a conversation was live.
func (r *callRegistry) releaseCall(instanceID, callID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if lc := r.calls[instanceID]; lc != nil && lc.CallID == callID {
		lc.end()
		delete(r.calls, instanceID)
	}
}

// drainInstance ends and forgets an instance's call, returning it so the caller can
// report the outcome. Used when a session is lost (FR-022).
func (r *callRegistry) drainInstance(instanceID string) *liveCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	lc := r.calls[instanceID]
	if lc == nil {
		return nil
	}
	lc.setState(CallStateEnded)
	delete(r.calls, instanceID)
	return lc
}
