package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"

	"wuzapi/internal/meowcaller"
)

// Feature 028 (T119): mídia nos dois sentidos e gravação da ligação da Cloud API.
//
// Um par do pion faz o papel da Meta. O teste estabelece a perna de verdade, pela rede local,
// e confere o que o motor promete: a voz do contato chega à ponte do atendente, a voz do
// atendente chega à Meta só depois de `established`, e a gravação concedida produz as duas
// trilhas.

type metaSide struct {
	pc       *webrtc.PeerConnection
	track    *webrtc.TrackLocalStaticSample
	received atomic.Int64
}

func newMetaSide(t *testing.T) *metaSide {
	t.Helper()
	side := &metaSide{pc: metaPeer(t)}
	for _, sender := range side.pc.GetSenders() {
		if track, ok := sender.Track().(*webrtc.TrackLocalStaticSample); ok {
			side.track = track
		}
	}
	side.pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		for {
			if _, _, err := remote.ReadRTP(); err != nil {
				return
			}
			side.received.Add(1)
		}
	})
	return side
}

// speak envia voz da Meta por `d`, em quadros de 20 ms.
func (m *metaSide) speak(t *testing.T, d time.Duration) {
	t.Helper()
	encoder, err := newOpusEncoder()
	if err != nil {
		t.Fatalf("encoder: %v", err)
	}
	defer encoder.Close()
	tone := make([]float32, cloudFrameSamples)
	for i := range tone {
		tone[i] = 0.2
	}
	for elapsed := time.Duration(0); elapsed < d; elapsed += cloudFrameDuration {
		packet, err := encoder.EncodeFrame(tone)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_ = m.track.WriteSample(media.Sample{Data: packet, Duration: cloudFrameDuration})
		time.Sleep(cloudFrameDuration)
	}
}

func waitUntil(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// connectIncoming atende uma ligação recebida com o par da Meta e espera a conexão.
func connectIncoming(t *testing.T, s *server, record bool) (*metaSide, *agentSession, *cloudCall) {
	t.Helper()
	session, _ := captureSession(t, "op-1")
	meta := newMetaSide(t)

	offer, err := meta.pc.CreateOffer(nil)
	if err != nil {
		t.Fatalf("meta offer: %v", err)
	}
	offerSDP, err := gatherLocal(meta.pc, offer)
	if err != nil {
		t.Fatalf("meta gather: %v", err)
	}

	call, answer, err := s.cloudEngine().accept(testCloudInstance, "wacid.media", "op-1", offerSDP, cloudContact{}, record)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := meta.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		t.Fatalf("meta remote: %v", err)
	}
	waitUntil(t, "media connection", 10*time.Second, func() bool {
		return meta.pc.ConnectionState() == webrtc.PeerConnectionStateConnected
	})
	return meta, session, call
}

func TestCloudCallMediaFlowsBothWays(t *testing.T) {
	s, _ := setupCloudRoutes(t)
	meta, session, _ := connectIncoming(t, s, false)

	var heard atomic.Int64
	session.Bridge().SetPeerSink(func(frame []float32) {
		if len(frame) == meowcaller.FrameSamples {
			heard.Add(1)
		}
	})

	// Antes de `established`, a perna não fala.
	time.Sleep(200 * time.Millisecond)
	if meta.received.Load() != 0 {
		t.Fatalf("Meta received %d packets before established", meta.received.Load())
	}

	if err := s.cloudEngine().established(testCloudInstance, "wacid.media"); err != nil {
		t.Fatalf("established: %v", err)
	}
	meta.speak(t, 600*time.Millisecond)

	waitUntil(t, "contact audio at the bridge", 5*time.Second, func() bool { return heard.Load() > 0 })
	waitUntil(t, "agent audio at Meta", 5*time.Second, func() bool { return meta.received.Load() > 0 })
}

func TestCloudCallRecordingDeliversBothTracks(t *testing.T) {
	s, emitted := setupCloudRoutes(t)
	meta, _, call := connectIncoming(t, s, true)

	if err := s.cloudEngine().established(testCloudInstance, "wacid.media"); err != nil {
		t.Fatalf("established: %v", err)
	}
	call.mu.Lock()
	recording := call.recorder != nil
	call.mu.Unlock()
	if !recording {
		t.Fatal("a granted recording must start at established")
	}

	meta.speak(t, 1500*time.Millisecond)
	s.cloudEngine().end(testCloudInstance, "wacid.media", "COMPLETED")

	waitUntil(t, "recording event", 5*time.Second, func() bool { return len(emitted.types()) > 0 })
	emitted.mu.Lock()
	event := emitted.events[0]
	emitted.mu.Unlock()
	if event["type"] != "CallRecordingReady" {
		t.Fatalf("event = %v, want CallRecordingReady", event["type"])
	}
	data := event["event"].(map[string]any)
	if data["CallID"] != "wacid.media" || data["RemoteTrackToken"] == "" || data["LocalTrackToken"] == "" {
		t.Fatalf("recording event = %v", data)
	}
	if seconds, _ := data["DurationSeconds"].(int); seconds < 1 {
		t.Fatalf("DurationSeconds = %v, want at least 1", data["DurationSeconds"])
	}
	if event["instanceName"] != testCloudInstance {
		t.Fatalf("instanceName = %v", event["instanceName"])
	}
}

func TestCloudCallWithoutGrantRecordsNothing(t *testing.T) {
	s, emitted := setupCloudRoutes(t)
	meta, _, call := connectIncoming(t, s, false)

	if err := s.cloudEngine().established(testCloudInstance, "wacid.media"); err != nil {
		t.Fatalf("established: %v", err)
	}
	meta.speak(t, 300*time.Millisecond)

	call.mu.Lock()
	recording := call.recorder != nil
	call.mu.Unlock()
	if recording {
		t.Fatal("no recorder without a granted recording")
	}
	s.cloudEngine().end(testCloudInstance, "wacid.media", "COMPLETED")
	time.Sleep(100 * time.Millisecond)
	if got := emitted.types(); len(got) != 0 {
		t.Fatalf("emitted %v, want nothing", got)
	}
}
