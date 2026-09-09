package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"wuzapi/internal/meowcaller"

	"github.com/rs/zerolog/log"
)

// Recording capture (feature 020, research §R4).
//
// meowcaller hands over only the PEER's audio: Call.Receive delivers the frames it
// decodes from the remote side, and nothing mirrors what we play out. FR-028 wants
// both sides in one file, so the two legs are captured separately here and mixed by
// media-processor -- the only repository allowed to run ffmpeg (Princípio I).
//
// The two tracks share ONE timeline, which is what makes the mix a plain overlay
// instead of an alignment problem: every frame written to the remote track writes
// exactly one frame to the local track too, filled with the audio being played or
// with silence when nothing is. The remote stream is the clock.

// recordingFrameLimit caps a recording at one hour (FR-048).
//
// 60 ms per frame at 16 kHz, so 3600 s is 60000 frames. Counting frames rather than
// wall-clock ties the limit to the audio actually captured -- a call that stalls does
// not burn the budget.
const recordingFrameLimit = 3600 * 1000 / 60

// silentFrame is written to the local track whenever no audio is playing. Shared and
// never mutated: WriteFrame only reads it.
var silentFrame = make([]float32, meowcaller.FrameSamples)

// callRecorder captures both legs of a call to two WAV files of equal length.
type callRecorder struct {
	mu sync.Mutex

	remote meowcaller.AudioSink
	local  meowcaller.AudioSink

	RemotePath string
	LocalPath  string

	// pending holds frames the player has produced but that no remote frame has
	// claimed a slot for yet. Bounded: a player running ahead of the peer's stream
	// must not grow this without limit.
	pending [][]float32

	frames    int
	truncated bool
	closed    bool
	startedAt time.Time
}

// maxPendingFrames bounds the playout buffer at ~3 s of audio.
//
// The player and the peer's stream are independent clocks. A small buffer absorbs
// jitter; a large one would let a fast player queue minutes of audio that would land
// in the wrong place on the timeline. Overflow drops the oldest frame -- the
// recording loses a moment, the call does not.
const maxPendingFrames = 50

// newCallRecorder opens the two tracks for a call.
func newCallRecorder(instanceID, callID string) (*callRecorder, error) {
	// The ids go into the directory name so an operator inspecting leftover files on
	// disk can tell which call they belong to without cross-referencing anything.
	dir, err := os.MkdirTemp("", fmt.Sprintf("call-%s-%s-*", instanceID, callID))
	if err != nil {
		return nil, err
	}

	remotePath := fmt.Sprintf("%s/remote.wav", dir)
	localPath := fmt.Sprintf("%s/local.wav", dir)

	remote, err := meowcaller.WAVRecorder(remotePath)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	local, err := meowcaller.WAVRecorder(localPath)
	if err != nil {
		remote.Close()
		os.RemoveAll(dir)
		return nil, err
	}

	return &callRecorder{
		remote:     remote,
		local:      local,
		RemotePath: remotePath,
		LocalPath:  localPath,
		startedAt:  time.Now(),
	}, nil
}

// Sink is the AudioSink handed to Call.Receive. It is the recorder's clock: each
// remote frame advances both tracks by exactly one frame.
func (r *callRecorder) Sink() meowcaller.AudioSink {
	return meowcaller.SinkFunc(func(frame []float32) {
		r.writeFrame(frame)
	})
}

func (r *callRecorder) writeFrame(remoteFrame []float32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed || r.truncated {
		return
	}

	// One hour reached: stop recording, keep the call running. The contact hears no
	// interruption whatsoever (FR-048, US4-AS8).
	if r.frames >= recordingFrameLimit {
		r.truncated = true
		return
	}

	_ = r.remote.WriteFrame(remoteFrame)

	// The matching slot on the local track: the audio being played, or silence. This
	// is what keeps the two files the same length.
	localFrame := silentFrame
	if len(r.pending) > 0 {
		localFrame = r.pending[0]
		r.pending = r.pending[1:]
	}
	_ = r.local.WriteFrame(localFrame)

	r.frames++
}

// WrapSource tees an audio source into the local track.
//
// Wrapping the source, rather than reading the player, is what makes the capture
// independent of how the engine schedules playout: every frame the call consumes is
// a frame the recording sees.
func (r *callRecorder) WrapSource(src meowcaller.AudioSource) meowcaller.AudioSource {
	return &recordingSource{src: src, rec: r}
}

func (r *callRecorder) pushPlayed(frame []float32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.truncated {
		return
	}
	// Copy: the source may reuse its frame buffer between reads, and this frame is
	// held until a remote frame claims its slot.
	buf := make([]float32, len(frame))
	copy(buf, frame)

	if len(r.pending) >= maxPendingFrames {
		r.pending = r.pending[1:]
	}
	r.pending = append(r.pending, buf)
}

// RecordingResult describes a finished capture.
type RecordingResult struct {
	RemotePath      string
	LocalPath       string
	DurationSeconds int
	Truncated       bool
}

// Close finalizes both tracks and reports what was captured.
//
// Always produces a usable result, even when the call ended abruptly: whatever was
// captured up to that point is what the customer receives (FR-029).
func (r *callRecorder) Close() RecordingResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		_ = r.remote.Close()
		_ = r.local.Close()
	}
	return RecordingResult{
		RemotePath:      r.RemotePath,
		LocalPath:       r.LocalPath,
		DurationSeconds: r.frames * 60 / 1000,
		Truncated:       r.truncated,
	}
}

// Discard closes the tracks and deletes them, leaving nothing behind.
//
// Used when the recording must not be delivered -- so that a call the platform was
// not allowed to record retains no audio at all (FR-027).
func (r *callRecorder) Discard() {
	result := r.Close()
	os.RemoveAll(dirOf(result.RemotePath))
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return path
}

// recordingSource is the tee: it forwards frames to the call and copies them into the
// local track.
type recordingSource struct {
	src meowcaller.AudioSource
	rec *callRecorder
}

func (s *recordingSource) ReadFrame() ([]float32, error) {
	frame, err := s.src.ReadFrame()
	if err == nil {
		s.rec.pushPlayed(frame)
	}
	return frame, err
}

func (s *recordingSource) Close() error { return s.src.Close() }

// ---- Serving the captured tracks ----
//
// The tracks have to reach media-processor, the only service allowed to mix them
// (Princípio I). They cannot go through S3 from here: this server's S3 is a
// per-customer, opt-in feature -- most instances have none, and it holds the
// customer's own bucket credentials, not the platform's.
//
// So the tracks are served over HTTP behind an unguessable path, and the platform
// passes those URLs to media-processor, which already knows how to fetch one.
// Nothing about the platform's storage leaks into this repository, and no audio
// travels through the API needlessly.

// recordingURLTTL bounds how long a track stays fetchable.
//
// The mix runs within seconds of the call ending; an hour is slack for a retry, not
// a window anyone should rely on. The voice of an identifiable person does not sit
// on disk longer than it must.
const recordingURLTTL = time.Hour

type servedTrack struct {
	path      string
	dir       string
	expiresAt time.Time
}

// recordingStore hands out short-lived tokens for the captured tracks.
type recordingStore struct {
	mu     sync.Mutex
	tracks map[string]servedTrack
}

var recordingStoreInstance = &recordingStore{tracks: make(map[string]servedTrack)}

// GetRecordingStore returns the process-wide store.
func GetRecordingStore() *recordingStore { return recordingStoreInstance }

// publish registers a track and returns its token.
//
// Tokens are 32 bytes from crypto/rand: the path IS the credential, so guessing it
// must be out of reach. They are not single-use, so a retried mix can fetch the same
// track again instead of losing the recording to one transient failure.
func (s *recordingStore) publish(path, dir string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tracks[token] = servedTrack{
		path:      path,
		dir:       dir,
		expiresAt: time.Now().Add(recordingURLTTL),
	}
	return token, nil
}

// resolve returns the file path for a token, or false when it is unknown or expired.
func (s *recordingStore) resolve(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	track, ok := s.tracks[token]
	if !ok {
		return "", false
	}
	if time.Now().After(track.expiresAt) {
		delete(s.tracks, token)
		os.RemoveAll(track.dir)
		return "", false
	}
	return track.path, true
}

// sweep drops expired tracks and deletes their files.
//
// Without it, a recording nobody fetched would keep its audio on disk for the life
// of the process.
func (s *recordingStore) sweep() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, track := range s.tracks {
		if now.After(track.expiresAt) {
			delete(s.tracks, token)
			os.RemoveAll(track.dir)
		}
	}
}

// StartRecordingSweeper runs the expiry sweep for the life of the process.
func StartRecordingSweeper() {
	safeGo("recordingSweeper", func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			GetRecordingStore().sweep()
		}
	})
}

// publishRecordingTracks registers both legs of a finished recording for pickup.
func publishRecordingTracks(result RecordingResult) (remoteToken, localToken string, err error) {
	dir := dirOf(result.RemotePath)
	remoteToken, err = GetRecordingStore().publish(result.RemotePath, dir)
	if err != nil {
		return "", "", err
	}
	localToken, err = GetRecordingStore().publish(result.LocalPath, dir)
	if err != nil {
		return "", "", err
	}
	log.Debug().
		Int("duration_seconds", result.DurationSeconds).
		Msg("Recording tracks published for pickup")
	return remoteToken, localToken, nil
}
