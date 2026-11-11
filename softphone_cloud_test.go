package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// Feature 028 (T102): a sessão do softphone em instância `cloud_api`.

const testCloudInstance = "inst_cloud_da_plataforma"

// seedCloudInstance cadastra a instância neste servidor, sem sessão de WhatsApp.
func seedCloudInstance(t *testing.T, s *server) {
	t.Helper()
	if _, err := s.db.Exec(
		`INSERT INTO users (id, name, token, connected) VALUES ($1,$2,$3,$4)`,
		"9c1d2e3f", testCloudInstance, testCloudInstance, 0); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func dialSoftphone(t *testing.T, ctx context.Context, s *server, claims agentTokenClaims) *websocket.Conn {
	t.Helper()
	srv := httptest.NewServer(s.router)
	t.Cleanup(srv.Close)

	conn, _, err := websocket.Dial(ctx,
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/softphone",
		&websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{testCRMOrigin}}})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })

	open, _ := json.Marshal(map[string]any{
		"t":  "session.open",
		"id": "1",
		"d":  map[string]any{"token": signAgentToken(t, testAgentSecret, claims)},
	})
	if err := conn.Write(ctx, websocket.MessageText, open); err != nil {
		t.Fatalf("write session.open: %v", err)
	}
	return conn
}

func cloudClaims(agentID string) agentTokenClaims {
	claims := baseAgentClaims()
	claims.InstanceID = testCloudInstance
	claims.Origin = testCRMOrigin
	claims.InstanceType = instanceTypeCloudAPI
	claims.Subject = agentID
	return claims
}

func readFrame(t *testing.T, ctx context.Context, conn *websocket.Conn) softphoneFrame {
	t.Helper()
	frame, err := readSoftphoneFrame(ctx, conn)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return frame
}

func cleanupSoftphoneRegistry(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		GetSoftphoneRegistry().closeInstance(testCloudInstance, closeReasonServerShutdown)
		GetCloudCallRegistry().drainInstance(testCloudInstance)
	})
}

func TestCloudSessionOpensWithoutWhatsAppSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := makeTestServer(t)
	withSoftphoneSecret(t, testAgentSecret)
	seedCloudInstance(t, s)
	cleanupSoftphoneRegistry(t)

	conn := dialSoftphone(t, ctx, s, cloudClaims("op-1"))
	frame := readFrame(t, ctx, conn)
	if frame.T != "session.ready" {
		t.Fatalf("frame = %s %s, want session.ready", frame.T, frame.D)
	}

	session := GetSoftphoneRegistry().session(testCloudInstance, "op-1")
	if session == nil || !session.IsCloud() {
		t.Fatal("cloud session must be registered under the platform instance id")
	}
}

func TestDeviceTokenStillRequiresWhatsAppSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := makeTestServer(t)
	withSoftphoneSecret(t, testAgentSecret)
	seedCloudInstance(t, s)
	cleanupSoftphoneRegistry(t)

	claims := cloudClaims("op-1")
	claims.InstanceType = "" // credencial sem `itp`: comportamento do `device`
	conn := dialSoftphone(t, ctx, s, claims)

	frame := readFrame(t, ctx, conn)
	if frame.T != "session.error" || !strings.Contains(string(frame.D), "INSTANCE_NOT_CONNECTED") {
		t.Fatalf("frame = %s %s, want INSTANCE_NOT_CONNECTED", frame.T, frame.D)
	}
}

func TestCloudSessionRefusedForInstanceOfAnotherServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := makeTestServer(t)
	withSoftphoneSecret(t, testAgentSecret)
	cleanupSoftphoneRegistry(t)

	conn := dialSoftphone(t, ctx, s, cloudClaims("op-1"))
	frame := readFrame(t, ctx, conn)
	if frame.T != "session.error" {
		t.Fatalf("frame = %s, want session.error for an instance unknown here", frame.T)
	}
}

// captureSession abre uma sessão `cloud_api` sem socket, guardando os quadros publicados.
func captureSession(t *testing.T, agentID string) (*agentSession, *frameLog) {
	t.Helper()
	log := &frameLog{}
	session := GetSoftphoneRegistry().openCloud(testCloudInstance, agentIdentity{ID: agentID})
	session.attach(log.add)
	return session, log
}

func TestCloudIncomingGoesOnlyToFreeAgents(t *testing.T) {
	cleanupSoftphoneRegistry(t)
	busy, busyLog := captureSession(t, "op-busy")
	_, freeLog := captureSession(t, "op-free")
	busy.setConductingCall("wacid.ongoing")

	n := publishCloudIncoming(testCloudInstance, "wacid.new", cloudContact{JID: "5511999990000@s.whatsapp.net"}, time.Now())

	if n != 1 {
		t.Fatalf("signalled = %d, want 1", n)
	}
	if busyLog.count("call.incoming") != 0 {
		t.Fatal("agent in a call must not be signalled")
	}
	if freeLog.count("call.incoming") != 1 {
		t.Fatal("free agent must be signalled")
	}
}

func TestCloudClearedGoesToEveryAgent(t *testing.T) {
	cleanupSoftphoneRegistry(t)
	_, a := captureSession(t, "op-1")
	_, b := captureSession(t, "op-2")

	publishIncomingCleared(testCloudInstance, "wacid.1", incomingClearedAnswered)

	for _, log := range []*frameLog{a, b} {
		frame := log.last("call.incoming.cleared")
		if frame == nil || frame["reason"] != incomingClearedAnswered {
			t.Fatalf("cleared frame = %v, want ANSWERED_ELSEWHERE", frame)
		}
	}
}

func TestCloudLineIsPerAgent(t *testing.T) {
	cleanupSoftphoneRegistry(t)
	busy, busyLog := captureSession(t, "op-busy")
	_, freeLog := captureSession(t, "op-free")
	busy.setConductingCall("wacid.1")

	publishCloudLineState(testCloudInstance)

	if line := busyLog.last("line.update"); line == nil || line["busy"] != true || line["callId"] != "wacid.1" {
		t.Fatalf("busy agent line = %v", line)
	}
	if line := freeLog.last("line.update"); line == nil || line["busy"] != false {
		t.Fatalf("free agent line = %v, want busy=false", line)
	}
}
