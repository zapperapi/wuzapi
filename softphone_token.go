package main

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Verificação da credencial do atendente (feature 021, research §R7).
//
// O `zapperapi-manager` emite; este arquivo confere. Os dois compartilham o segredo, e é
// isso que permite ao navegador abrir a sessão de tempo real aqui sem que o `wuzapi`
// precise consultar o `manager` a cada conexão.
//
// A credencial NÃO dá acesso à API da instância. A rota do softphone fica fora da cadeia
// `authalice`, então um token de atendente não alcança mensagens, contatos nem qualquer
// outro recurso (FR-061).

const (
	// agentTokenIssuer precisa casar com AGENT_TOKEN_ISSUER do manager.
	agentTokenIssuer = "zapperhub"
	// agentScopeCalls é o único escopo desta versão.
	agentScopeCalls = "calls"
)

// errAgentTokenInvalid é a recusa única de credencial expirada, adulterada ou desconhecida.
//
// Um erro só para os três casos, de propósito (FR-009): distinguir "expirou" de "não existe"
// conta a quem tem um token qualquer se ele já foi válido. A causa real fica no log.
var errAgentTokenInvalid = errors.New("softphone: invalid agent credential")

// errAgentTokenScope é a recusa por escopo: a identidade foi provada, a permissão não existe.
var errAgentTokenScope = errors.New("softphone: credential is not allowed to conduct calls")

// agentIdentity é o que a credencial carrega até aqui. Opaca: o identificador e o nome vêm
// do sistema do cliente, e nada além deles é armazenado (FR-059).
type agentIdentity struct {
	ID          string
	DisplayName string
	// JTI identifica a emissão no log, sem que o token precise ser registrado.
	JTI string
	// Origin é a origem do CRM do cliente, cadastrada no manager e estampada pelo emissor.
	// Confrontada contra o cabeçalho `Origin` do handshake em `authenticateSoftphone` —
	// a validação por lista global (`SOFTPHONE_ALLOWED_ORIGINS`) não serve a uma frota
	// multi-tenant, onde cada instância neste mesmo servidor pode ter um CRM diferente.
	Origin string
}

// agentTokenClaims espelha as reivindicações emitidas pelo manager.
type agentTokenClaims struct {
	InstanceID string `json:"iid"`
	Scope      string `json:"scope"`
	Name       string `json:"name,omitempty"`
	Origin     string `json:"origin"`
	jwt.RegisteredClaims
}

// parseAgentToken confere assinatura, emissor, vencimento e escopo, e devolve a identidade
// do atendente junto da instância a que a credencial está presa.
//
// A instância vem **do token**, e não do endereço: o socket é `/softphone`, sem instância no
// caminho. Isso não afrouxa o isolamento — ao contrário, elimina a possibilidade de
// divergência entre o que o cliente pede e o que a credencial autoriza. Quem confere se essa
// instância existe *neste* servidor é o chamador, porque é ele que sabe (FR-007).
func parseAgentToken(raw string) (agentIdentity, string, error) {
	if !softphone.enabled {
		return agentIdentity{}, "", errAgentTokenInvalid
	}

	claims := &agentTokenClaims{}
	// jwt.WithValidMethods fecha a confusão de algoritmo: sem ela, um token com `alg: none`
	// ou assinado com um algoritmo assimétrico seria aceito com a chave errada.
	_, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (interface{}, error) {
		return softphone.tokenSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(agentTokenIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return agentIdentity{}, "", fmt.Errorf("%w: %s", errAgentTokenInvalid, err)
	}

	// Escopo antes de identidade: um token bem assinado com escopo errado é um pedido
	// legítimo de permissão que não temos.
	if claims.Scope != agentScopeCalls {
		return agentIdentity{}, "", errAgentTokenScope
	}

	if claims.Subject == "" || claims.InstanceID == "" || claims.Origin == "" {
		return agentIdentity{}, "", errAgentTokenInvalid
	}

	return agentIdentity{
		ID:          claims.Subject,
		DisplayName: claims.Name,
		JTI:         claims.ID,
		Origin:      claims.Origin,
	}, claims.InstanceID, nil
}
