package main

import (
	"os"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// Configuração do softphone (feature 021-audio-bidirecional).
//
// Vive em um arquivo próprio, e não no bloco de ambiente do main.go, porque é um conjunto
// coeso: sem o segredo não há sessão, e sem as portas não há mídia. Ler as cinco variáveis
// juntas deixa a falha de configuração óbvia na subida, em vez de virar uma chamada muda
// depois.
const (
	defaultSoftphoneMediaUDPPort = 3478
	defaultSoftphoneMediaTCPPort = 3479
)

// softphoneConfig é a configuração resolvida. `enabled` é falso quando o segredo não foi
// informado: o servidor sobe normalmente e apenas o softphone fica indisponível — uma
// instalação que não usa a feature não deveria deixar de subir por causa dela.
type softphoneConfig struct {
	enabled bool

	// tokenSecret assina e verifica a credencial do atendente. Precisa ser idêntico ao
	// SOFTPHONE_TOKEN_SECRET do zapperapi-manager, que é quem emite.
	tokenSecret []byte

	// allowedOrigins são as origens aceitas no handshake do WebSocket.
	//
	// Não é CORS: handshake de WebSocket não dispara preflight. O navegador manda `Origin` e
	// cabe a nós aceitar. Lista vazia recusa toda origem cruzada — falha fechada, de
	// propósito. O curinga "*" existe só para desenvolvimento.
	allowedOrigins []string

	// publicIP é o endereço anunciado como candidato host no SDP. Sem ele, o navegador
	// recebe o IP interno do contêiner e nenhuma mídia se estabelece.
	publicIP string

	mediaUDPPort int
	mediaTCPPort int
}

var softphone softphoneConfig

// loadSoftphoneConfig lê o ambiente e reporta o que ficou valendo.
//
// O segredo nunca é registrado em log, nem truncado, nem por prefixo: um prefixo de chave
// HS256 em log é um pedaço de chave em log (Princípio VI).
func loadSoftphoneConfig() {
	secret := os.Getenv("SOFTPHONE_TOKEN_SECRET")
	if secret == "" {
		log.Info().Msg("SOFTPHONE_TOKEN_SECRET not set, softphone sessions are disabled")
		return
	}
	if len(secret) < 32 {
		log.Error().
			Int("length", len(secret)).
			Msg("SOFTPHONE_TOKEN_SECRET is shorter than 32 characters, softphone sessions are disabled")
		return
	}

	softphone = softphoneConfig{
		enabled:        true,
		tokenSecret:    []byte(secret),
		allowedOrigins: parseAllowedOrigins(os.Getenv("SOFTPHONE_ALLOWED_ORIGINS")),
		publicIP:       os.Getenv("SOFTPHONE_PUBLIC_IP"),
		mediaUDPPort:   envPort("SOFTPHONE_MEDIA_UDP_PORT", defaultSoftphoneMediaUDPPort),
		mediaTCPPort:   envPort("SOFTPHONE_MEDIA_TCP_PORT", defaultSoftphoneMediaTCPPort),
	}

	if softphone.publicIP == "" {
		log.Warn().Msg("SOFTPHONE_PUBLIC_IP not set, media will advertise the container address and will not reach browsers outside the host")
	}
	if len(softphone.allowedOrigins) == 0 {
		log.Warn().Msg("SOFTPHONE_ALLOWED_ORIGINS is empty, every cross-origin session will be refused")
	}

	log.Info().
		Int("media_udp_port", softphone.mediaUDPPort).
		Int("media_tcp_port", softphone.mediaTCPPort).
		Str("public_ip", softphone.publicIP).
		Int("allowed_origins", len(softphone.allowedOrigins)).
		Msg("Softphone configured")
}

// parseAllowedOrigins divide a lista separada por vírgula, descartando espaços e entradas
// vazias, e normaliza para minúsculas — comparação de origem é insensível a caixa no esquema
// e no host.
func parseAllowedOrigins(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.ToLower(strings.TrimSpace(part)); trimmed != "" {
			origins = append(origins, trimmed)
		}
	}
	return origins
}

// envPort lê uma porta do ambiente, caindo no padrão quando ausente ou inválida.
func envPort(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		log.Warn().Str("variable", name).Str("value", raw).Int("fallback", fallback).
			Msg("Invalid port in environment, using default")
		return fallback
	}
	return port
}
