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
	whatsmeow "github.com/polymorfa/hypermeow"
)

// A chave dos clientes em memória do wuzapi é o `users.id` — aleatório, gerado no
// cadastro do usuário — enquanto a credencial do atendente carrega na claim `iid` o
// identificador da plataforma, que é o *token* do usuário. São valores diferentes, e
// abrir a sessão sem traduzir um no outro procura a instância por uma chave que nunca
// existe: toda sessão morre em INSTANCE_NOT_CONNECTED, mesmo com a instância conectada.
const (
	testInstanceToken = "inst_token_da_plataforma"
	testWuzapiUserID  = "7f3c1a9e"
	testCRMOrigin     = "https://crm.cliente.test"
	testAgentSecret   = "a-secret-at-least-32-bytes-long!"
)

// openSoftphoneSession deixa uma instância conectada sob a chave interna do wuzapi e abre
// uma sessão de atendente com uma credencial que fala o identificador da plataforma —
// exatamente o par de valores que produção tem.
func openSoftphoneSession(t *testing.T, ctx context.Context) *websocket.Conn {
	t.Helper()

	s := makeTestServer(t)
	withSoftphoneSecret(t, testAgentSecret)

	if _, err := s.db.Exec(
		`INSERT INTO users (id, name, token, connected) VALUES ($1,$2,$3,$4)`,
		testWuzapiUserID, "tester", testInstanceToken, 1); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	clientManager.SetWhatsmeowClient(testWuzapiUserID, &whatsmeow.Client{})
	clientManager.SetMyClient(testWuzapiUserID, &MyClient{callEngine: &callEngine{}})
	t.Cleanup(func() {
		clientManager.DeleteWhatsmeowClient(testWuzapiUserID)
		clientManager.DeleteMyClient(testWuzapiUserID)
	})

	srv := httptest.NewServer(s.router)
	t.Cleanup(srv.Close)

	conn, _, err := websocket.Dial(ctx,
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/softphone",
		&websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{testCRMOrigin}}})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })

	claims := baseAgentClaims()
	claims.InstanceID = testInstanceToken
	claims.Origin = testCRMOrigin

	open, err := json.Marshal(map[string]any{
		"t":  "session.open",
		"id": "1",
		"d":  map[string]any{"token": signAgentToken(t, testAgentSecret, claims)},
	})
	if err != nil {
		t.Fatalf("encode session.open: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, open); err != nil {
		t.Fatalf("write session.open: %v", err)
	}
	return conn
}

func TestSoftphoneSessionOpensWhenUserIDDiffersFromToken(t *testing.T) {
	const (
		instanceToken = testInstanceToken
		wuzapiUserID  = testWuzapiUserID
		origin        = testCRMOrigin
		secret        = testAgentSecret
	)

	s := makeTestServer(t)
	withSoftphoneSecret(t, secret)

	if _, err := s.db.Exec(
		`INSERT INTO users (id, name, token, connected) VALUES ($1,$2,$3,$4)`,
		wuzapiUserID, "tester", instanceToken, 1); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// A instância está conectada sob a chave do wuzapi, como em produção.
	clientManager.SetWhatsmeowClient(wuzapiUserID, &whatsmeow.Client{})
	clientManager.SetMyClient(wuzapiUserID, &MyClient{callEngine: &callEngine{}})
	t.Cleanup(func() {
		clientManager.DeleteWhatsmeowClient(wuzapiUserID)
		clientManager.DeleteMyClient(wuzapiUserID)
	})

	srv := httptest.NewServer(s.router)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx,
		"ws"+strings.TrimPrefix(srv.URL, "http")+"/softphone",
		&websocket.DialOptions{HTTPHeader: http.Header{"Origin": []string{origin}}})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	claims := baseAgentClaims()
	claims.InstanceID = instanceToken
	claims.Origin = origin

	open, err := json.Marshal(map[string]any{
		"t":  "session.open",
		"id": "1",
		"d":  map[string]any{"token": signAgentToken(t, secret, claims)},
	})
	if err != nil {
		t.Fatalf("encode session.open: %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, open); err != nil {
		t.Fatalf("write session.open: %v", err)
	}

	frame, err := readSoftphoneFrame(ctx, conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if frame.T != "session.ready" {
		t.Fatalf("t = %q, want \"session.ready\" (d = %s)", frame.T, frame.D)
	}
}

// Uma chamada entrante é publicada pelo motor com o `users.id` (é o que `newCallEngine`
// recebe em wmiau.go). Se a sessão do atendente se registrar sob outro identificador, o
// aviso vai para um conjunto vazio: o telefone nunca toca, mesmo com tudo conectado.
func TestIncomingCallReachesSessionOpenedByCredential(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn := openSoftphoneSession(t, ctx)

	ready, err := readSoftphoneFrame(ctx, conn)
	if err != nil {
		t.Fatalf("read session.ready: %v", err)
	}
	if ready.T != "session.ready" {
		t.Fatalf("t = %q, want \"session.ready\" (d = %s)", ready.T, ready.D)
	}

	publishIncomingCall(testWuzapiUserID, "call-1", "5511999999999@s.whatsapp.net")

	frame, err := readSoftphoneFrame(ctx, conn)
	if err != nil {
		t.Fatalf("read call.incoming: %v", err)
	}
	if frame.T != "call.incoming" {
		t.Fatalf("t = %q, want \"call.incoming\" (d = %s)", frame.T, frame.D)
	}
}
