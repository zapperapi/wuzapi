package main

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// A claim `origin` substitui a lista estática `SOFTPHONE_ALLOWED_ORIGINS`: cada instância
// pode ter um CRM em domínio diferente, e só o manager sabe qual, no momento da emissão.
//
// Estes testes cobrem só o que `parseAgentToken` decide sozinho — a exigência da claim. A
// comparação contra o cabeçalho `Origin` do handshake é responsabilidade de
// `authenticateSoftphone`, exercitada pelo Cenário 1 do quickstart com um navegador de
// verdade, não por um teste de unidade.

func withSoftphoneSecret(t *testing.T, secret string) {
	t.Helper()
	previous := softphone
	softphone = softphoneConfig{enabled: true, tokenSecret: []byte(secret)}
	t.Cleanup(func() { softphone = previous })
}

func signAgentToken(t *testing.T, secret string, claims agentTokenClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return signed
}

func baseAgentClaims() agentTokenClaims {
	return agentTokenClaims{
		InstanceID: "inst_1",
		Scope:      agentScopeCalls,
		Origin:     "https://crm.cliente.com",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    agentTokenIssuer,
			Subject:   "op-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
}

func TestParseAgentTokenCarriesOrigin(t *testing.T) {
	secret := "a-secret-at-least-32-bytes-long!"
	withSoftphoneSecret(t, secret)

	raw := signAgentToken(t, secret, baseAgentClaims())

	agent, instanceID, err := parseAgentToken(raw)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if instanceID != "inst_1" {
		t.Errorf("instanceID = %q, want %q", instanceID, "inst_1")
	}
	if agent.Origin != "https://crm.cliente.com" {
		t.Errorf("agent.Origin = %q, want %q", agent.Origin, "https://crm.cliente.com")
	}
}

// Um token sem `origin` — emitido antes desta mudança, ou adulterado — é recusado como
// qualquer outra credencial inválida (FR-009): não há uma origem contra a qual comparar, e
// aceitar sem checagem devolveria exatamente o buraco que a claim existe para fechar.
func TestParseAgentTokenRejectsMissingOrigin(t *testing.T) {
	secret := "a-secret-at-least-32-bytes-long!"
	withSoftphoneSecret(t, secret)

	claims := baseAgentClaims()
	claims.Origin = ""
	raw := signAgentToken(t, secret, claims)

	_, _, err := parseAgentToken(raw)
	if err == nil {
		t.Fatal("expected token without origin to be rejected")
	}
}
