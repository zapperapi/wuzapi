package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// Feature 028 (T103): as sete rotas internas da ligação da Cloud API pelo softphone.

// frameLog guarda os quadros publicados a uma sessão sem socket.
type frameLog struct {
	mu     sync.Mutex
	frames []map[string]any
}

func (l *frameLog) add(frame any) {
	body, _ := json.Marshal(frame)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	l.mu.Lock()
	l.frames = append(l.frames, decoded)
	l.mu.Unlock()
}

func (l *frameLog) count(kind string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, f := range l.frames {
		if f["t"] == kind {
			n++
		}
	}
	return n
}

// last devolve o `d` do último quadro do tipo, ou nil.
func (l *frameLog) last(kind string) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.frames) - 1; i >= 0; i-- {
		if l.frames[i]["t"] == kind {
			d, _ := l.frames[i]["d"].(map[string]any)
			return d
		}
	}
	return nil
}

// emittedEvents captura os eventos que o motor entregaria ao manager.
type emittedEvents struct {
	mu     sync.Mutex
	events []map[string]any
}

func captureCloudEmits(t *testing.T) *emittedEvents {
	t.Helper()
	captured := &emittedEvents{}
	previous := cloudCallEmitOverride
	cloudCallEmitOverride = func(instanceID string, payload map[string]any) {
		payload["instanceName"] = instanceID
		captured.mu.Lock()
		captured.events = append(captured.events, payload)
		captured.mu.Unlock()
	}
	t.Cleanup(func() { cloudCallEmitOverride = previous })
	return captured
}

func (e *emittedEvents) types() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.events))
	for _, ev := range e.events {
		out = append(out, ev["type"].(string))
	}
	return out
}

// withCloudCeiling troca o registro do processo por um com o teto informado.
func withCloudCeiling(t *testing.T, max int) {
	t.Helper()
	GetCloudCallRegistry()
	previous := cloudCallRegistryInstance
	cloudCallRegistryInstance = newCloudCallRegistry(max)
	t.Cleanup(func() { cloudCallRegistryInstance = previous })
}

func postAdmin(t *testing.T, s *server, path string, body any, auth string) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %d %q: %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

const adminAuth = "test-admin-token"

// metaPeer faz o papel da Meta: uma `PeerConnection` comum do pion.
func metaPeer(t *testing.T) *webrtc.PeerConnection {
	t.Helper()
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("meta peer: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "audio", "meta")
	if err != nil {
		t.Fatalf("meta track: %v", err)
	}
	if _, err := pc.AddTrack(track); err != nil {
		t.Fatalf("meta add track: %v", err)
	}
	return pc
}

func metaOffer(t *testing.T) string {
	t.Helper()
	pc := metaPeer(t)
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatalf("meta offer: %v", err)
	}
	sdp, err := gatherLocal(pc, offer)
	if err != nil {
		t.Fatalf("meta gather: %v", err)
	}
	return sdp
}

func metaAnswer(t *testing.T, offer string) string {
	t.Helper()
	pc := metaPeer(t)
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		t.Fatalf("meta remote: %v", err)
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("meta answer: %v", err)
	}
	sdp, err := gatherLocal(pc, answer)
	if err != nil {
		t.Fatalf("meta gather: %v", err)
	}
	return sdp
}

func setupCloudRoutes(t *testing.T) (*server, *emittedEvents) {
	t.Helper()
	s := makeTestServer(t)
	cleanupSoftphoneRegistry(t)
	withCloudCeiling(t, 50)
	return s, captureCloudEmits(t)
}

func TestCloudCallRoutesRequireAdminAuth(t *testing.T) {
	s, _ := setupCloudRoutes(t)
	paths := []string{
		"/admin/cloud-calls/incoming",
		"/admin/cloud-calls/offer",
		"/admin/cloud-calls/wacid.1/cleared",
		"/admin/cloud-calls/leg_1/remote-answer",
		"/admin/cloud-calls/wacid.1/accept",
		"/admin/cloud-calls/wacid.1/established",
		"/admin/cloud-calls/wacid.1/end",
	}
	for _, path := range paths {
		if rec := postAdmin(t, s, path, map[string]any{"instanceId": testCloudInstance}, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth = %d, want 401", path, rec.Code)
		}
	}
}

func TestCloudCallOfferWithoutSessionIsConflict(t *testing.T) {
	s, _ := setupCloudRoutes(t)
	rec := postAdmin(t, s, "/admin/cloud-calls/offer",
		map[string]any{"instanceId": testCloudInstance, "agentId": "op-1"}, adminAuth)
	if rec.Code != http.StatusConflict || decodeBody(t, rec)["code"] != "NO_AGENT_SESSION" {
		t.Fatalf("offer without session = %d %s", rec.Code, rec.Body.String())
	}
}

func TestCloudCallOutgoingLifecycle(t *testing.T) {
	s, emitted := setupCloudRoutes(t)
	session, frames := captureSession(t, "op-1")

	rec := postAdmin(t, s, "/admin/cloud-calls/offer", map[string]any{
		"instanceId": testCloudInstance, "agentId": "op-1",
		"contact": map[string]any{"jid": "5511999990000@s.whatsapp.net"},
	}, adminAuth)
	if rec.Code != http.StatusOK {
		t.Fatalf("offer = %d %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	legID, _ := body["legId"].(string)
	offer, _ := body["sdp"].(string)
	if !strings.HasPrefix(legID, "leg_") {
		t.Fatalf("legId = %q", legID)
	}
	for _, want := range []string{"m=audio", "opus/48000", "a=fingerprint:", "a=ice-ufrag:", "a=candidate:"} {
		if !strings.Contains(strings.ToLower(offer), strings.ToLower(want)) {
			t.Errorf("offer lacks %q", want)
		}
	}
	if session.ConductingCall() != legID {
		t.Fatalf("session conducts %q, want the leg until the callId exists", session.ConductingCall())
	}

	// Segunda ligação do mesmo atendente: ligação em curso.
	again := postAdmin(t, s, "/admin/cloud-calls/offer",
		map[string]any{"instanceId": testCloudInstance, "agentId": "op-1"}, adminAuth)
	if again.Code != http.StatusConflict || decodeBody(t, again)["code"] != "AGENT_IN_CALL" {
		t.Fatalf("second offer = %d %s", again.Code, again.Body.String())
	}

	answer := metaAnswer(t, offer)
	rec = postAdmin(t, s, "/admin/cloud-calls/"+legID+"/remote-answer",
		map[string]any{"instanceId": testCloudInstance, "callId": "wacid.out", "sdp": answer}, adminAuth)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("remote-answer = %d %s", rec.Code, rec.Body.String())
	}
	if session.ConductingCall() != "wacid.out" {
		t.Fatalf("session conducts %q, want the Meta callId", session.ConductingCall())
	}

	rec = postAdmin(t, s, "/admin/cloud-calls/wacid.out/established",
		map[string]any{"instanceId": testCloudInstance}, adminAuth)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("established = %d", rec.Code)
	}
	if state := frames.last("call.state"); state == nil || state["state"] != "ACTIVE" || state["callId"] != "wacid.out" {
		t.Fatalf("call.state = %v, want ACTIVE", state)
	}

	rec = postAdmin(t, s, "/admin/cloud-calls/wacid.out/end",
		map[string]any{"instanceId": testCloudInstance, "reason": "TERMINATED_BY_BUSINESS"}, adminAuth)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("end = %d", rec.Code)
	}
	if state := frames.last("call.state"); state["state"] != "ENDED" || state["endedReason"] != "BY_AGENT" {
		t.Fatalf("call.state = %v, want ENDED BY_AGENT", state)
	}
	if session.ConductingCall() != "" || GetCloudCallRegistry().count(testCloudInstance) != 0 {
		t.Fatal("end must free the agent and the seat")
	}
	if line := frames.last("line.update"); line["busy"] != false {
		t.Fatalf("line after end = %v", line)
	}

	// Encerrar de novo não é erro, e não há gravação sem concessão.
	rec = postAdmin(t, s, "/admin/cloud-calls/wacid.out/end",
		map[string]any{"instanceId": testCloudInstance, "reason": "COMPLETED"}, adminAuth)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("repeated end = %d", rec.Code)
	}
	if len(emitted.types()) != 0 {
		t.Fatalf("emitted %v, want nothing", emitted.types())
	}
}

func TestCloudCallIncomingAcceptLifecycle(t *testing.T) {
	s, _ := setupCloudRoutes(t)
	_, winner := captureSession(t, "op-1")
	_, other := captureSession(t, "op-2")

	rec := postAdmin(t, s, "/admin/cloud-calls/incoming", map[string]any{
		"instanceId": testCloudInstance, "callId": "wacid.in",
		"contact": map[string]any{"jid": "5511999990000@s.whatsapp.net"},
		"at":      time.Now().UTC().Format(time.RFC3339),
	}, adminAuth)
	if rec.Code != http.StatusNoContent || winner.count("call.incoming") != 1 || other.count("call.incoming") != 1 {
		t.Fatalf("incoming = %d, frames %d/%d", rec.Code, winner.count("call.incoming"), other.count("call.incoming"))
	}

	rec = postAdmin(t, s, "/admin/cloud-calls/wacid.in/accept", map[string]any{
		"instanceId": testCloudInstance, "agentId": "op-1", "sdp": metaOffer(t),
	}, adminAuth)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept = %d %s", rec.Code, rec.Body.String())
	}
	answer, _ := decodeBody(t, rec)["sdp"].(string)
	if !strings.Contains(answer, "a=setup:active") {
		t.Fatal("the business side must be the DTLS client (a=setup:active)")
	}

	// Outro atendente tentando a mesma ligação.
	rec = postAdmin(t, s, "/admin/cloud-calls/wacid.in/accept", map[string]any{
		"instanceId": testCloudInstance, "agentId": "op-2", "sdp": metaOffer(t),
	}, adminAuth)
	if rec.Code != http.StatusConflict || decodeBody(t, rec)["code"] != "CALL_TAKEN" {
		t.Fatalf("second accept = %d %s", rec.Code, rec.Body.String())
	}

	rec = postAdmin(t, s, "/admin/cloud-calls/wacid.in/cleared",
		map[string]any{"instanceId": testCloudInstance, "reason": "ANSWERED_ELSEWHERE"}, adminAuth)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cleared = %d", rec.Code)
	}
	if cleared := other.last("call.incoming.cleared"); cleared["reason"] != "ANSWERED_ELSEWHERE" {
		t.Fatalf("cleared frame = %v", cleared)
	}

	// Uma ligação nova não toca para quem está em ligação.
	postAdmin(t, s, "/admin/cloud-calls/incoming",
		map[string]any{"instanceId": testCloudInstance, "callId": "wacid.second"}, adminAuth)
	if winner.count("call.incoming") != 1 || other.count("call.incoming") != 2 {
		t.Fatalf("second incoming reached %d/%d", winner.count("call.incoming"), other.count("call.incoming"))
	}
}

func TestCloudCallCeilingIsTooManyRequests(t *testing.T) {
	s, _ := setupCloudRoutes(t)
	withCloudCeiling(t, 1)
	captureSession(t, "op-1")
	captureSession(t, "op-2")

	if rec := postAdmin(t, s, "/admin/cloud-calls/offer",
		map[string]any{"instanceId": testCloudInstance, "agentId": "op-1"}, adminAuth); rec.Code != http.StatusOK {
		t.Fatalf("first offer = %d", rec.Code)
	}
	rec := postAdmin(t, s, "/admin/cloud-calls/offer",
		map[string]any{"instanceId": testCloudInstance, "agentId": "op-2"}, adminAuth)
	if rec.Code != http.StatusTooManyRequests || decodeBody(t, rec)["code"] != "CONCURRENCY_LIMIT" {
		t.Fatalf("offer over the ceiling = %d %s", rec.Code, rec.Body.String())
	}
}

func TestCloudCallMediaFailureIsBadGateway(t *testing.T) {
	s, _ := setupCloudRoutes(t)
	session, _ := captureSession(t, "op-1")

	rec := postAdmin(t, s, "/admin/cloud-calls/wacid.bad/accept", map[string]any{
		"instanceId": testCloudInstance, "agentId": "op-1", "sdp": "v=0 not an sdp",
	}, adminAuth)
	if rec.Code != http.StatusBadGateway || decodeBody(t, rec)["code"] != "MEDIA_NEGOTIATION_FAILED" {
		t.Fatalf("accept with bad sdp = %d %s", rec.Code, rec.Body.String())
	}
	if session.ConductingCall() != "" || GetCloudCallRegistry().count(testCloudInstance) != 0 {
		t.Fatal("a failed negotiation must leave the agent free")
	}
}

func TestCloudCallUnknownLegIsNotFound(t *testing.T) {
	s, _ := setupCloudRoutes(t)
	rec := postAdmin(t, s, "/admin/cloud-calls/leg_missing/remote-answer",
		map[string]any{"instanceId": testCloudInstance, "callId": "wacid.x", "sdp": "v=0"}, adminAuth)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("remote-answer for unknown leg = %d", rec.Code)
	}
	rec = postAdmin(t, s, "/admin/cloud-calls/wacid.x/established",
		map[string]any{"instanceId": testCloudInstance}, adminAuth)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("established for unknown call = %d", rec.Code)
	}
}

func TestCloudCallAgentLostEmitsMediaLost(t *testing.T) {
	s, emitted := setupCloudRoutes(t)
	session, frames := captureSession(t, "op-1")
	postAdmin(t, s, "/admin/cloud-calls/wacid.in/accept", map[string]any{
		"instanceId": testCloudInstance, "agentId": "op-1", "sdp": metaOffer(t),
	}, adminAuth)

	s.cloudEngine().agentLost(testCloudInstance, session)

	if got := emitted.types(); len(got) != 1 || got[0] != "CloudCallMediaLost" {
		t.Fatalf("emitted = %v, want CloudCallMediaLost", got)
	}
	if state := frames.last("call.state"); state["endedReason"] != "FAILED" {
		t.Fatalf("call.state = %v, want FAILED", state)
	}
}
