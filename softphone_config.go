package main

import (
	"net"
	"os"
	"strconv"

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
	//
	// A origem do handshake não é validada por uma lista fixa aqui: cada instância pode ter
	// um CRM em domínio diferente, e a claim `origin` da própria credencial (ver
	// softphone_token.go) é quem carrega qual origem vale para *aquela* instância.
	tokenSecret []byte

	// publicIP é o endereço anunciado como candidato host no SDP. Sem ele, o navegador
	// recebe o IP interno do contêiner e nenhuma mídia se estabelece.
	publicIP string

	mediaUDPPort int
	mediaTCPPort int

	// mediaSubnet restringe a mídia a uma única interface, pela sub-rede dela.
	//
	// Um contêiner em Swarm é multi-homed: uma perna na overlay, por onde ele fala com o
	// banco, e outra na `docker_gwbridge`, por onde entra o tráfego publicado em
	// `mode: host`. Sem restrição, o agente ICE coleta e liga nas duas, e nada garante que
	// a sessão viva na mesma interface por onde o navegador chega — quando não vive, as
	// verificações de conectividade são descartadas sem resposta e o ICE nunca fecha.
	//
	// Por sub-rede, e não por IP ou nome de interface, porque é o único dos três que
	// sobrevive à recriação do contêiner: o IP muda e o nome depende da ordem em que as
	// redes são anexadas.
	//
	// Nulo significa "todas as interfaces", que é o certo para instalação de nó único.
	mediaSubnet *net.IPNet
}

// allowsMediaIP responde se um endereço local pode carregar mídia.
func (c softphoneConfig) allowsMediaIP(ip net.IP) bool {
	if c.mediaSubnet == nil {
		return true
	}
	return c.mediaSubnet.Contains(ip)
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
		enabled:      true,
		tokenSecret:  []byte(secret),
		publicIP:     os.Getenv("SOFTPHONE_PUBLIC_IP"),
		mediaUDPPort: envPort("SOFTPHONE_MEDIA_UDP_PORT", defaultSoftphoneMediaUDPPort),
		mediaTCPPort: envPort("SOFTPHONE_MEDIA_TCP_PORT", defaultSoftphoneMediaTCPPort),
		mediaSubnet:  envSubnet("SOFTPHONE_MEDIA_SUBNET"),
	}

	if softphone.publicIP == "" {
		log.Warn().Msg("SOFTPHONE_PUBLIC_IP not set, media will advertise the container address and will not reach browsers outside the host")
	}

	subnet := "todas as interfaces"
	if softphone.mediaSubnet != nil {
		subnet = softphone.mediaSubnet.String()
	}

	log.Info().
		Int("media_udp_port", softphone.mediaUDPPort).
		Int("media_tcp_port", softphone.mediaTCPPort).
		Str("public_ip", softphone.publicIP).
		Str("media_subnet", subnet).
		Msg("Softphone configured")
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

// envSubnet lê uma sub-rede CIDR do ambiente.
//
// Valor inválido **não** derruba a mídia: cai em "todas as interfaces", que é o
// comportamento de antes desta opção existir. Um erro de digitação aqui viraria chamada
// muda em todas as instâncias do servidor, e chamada muda é o sintoma mais caro de
// diagnosticar desta feature — o log avisa, a mídia continua de pé.
func envSubnet(name string) *net.IPNet {
	raw := os.Getenv(name)
	if raw == "" {
		return nil
	}
	_, subnet, err := net.ParseCIDR(raw)
	if err != nil {
		log.Warn().Str("variable", name).Str("value", raw).
			Msg("Invalid CIDR in environment, media will use every interface")
		return nil
	}
	return subnet
}
