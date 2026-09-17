package main

import (
	"net"
	"testing"
)

// restoreSoftphoneConfig devolve a configuração global ao fim do teste: ela é um singleton
// de processo, e vazar estado daqui contamina qualquer teste que toque no softphone.
func restoreSoftphoneConfig(t *testing.T) {
	t.Helper()
	previous := softphone
	t.Cleanup(func() { softphone = previous })
}

const testMediaSecret = "a-secret-at-least-32-bytes-long!"

// O contêiner do wuzapi é multi-homed: uma perna na overlay do Swarm e outra na
// docker_gwbridge, que é por onde entra o tráfego publicado em `mode: host`. Sem restringir,
// o agente ICE trabalha na interface errada e as verificações do navegador chegam a um mux
// que não conhece a sessão — descartadas em silêncio, ICE eternamente em `checking`.
func TestMediaSubnetRestringeABindNaInterfaceExterna(t *testing.T) {
	t.Setenv("SOFTPHONE_TOKEN_SECRET", testMediaSecret)
	t.Setenv("SOFTPHONE_MEDIA_SUBNET", "172.18.0.0/16")
	restoreSoftphoneConfig(t)
	loadSoftphoneConfig()

	if !softphone.allowsMediaIP(net.ParseIP("172.18.0.4")) {
		t.Error("IP da docker_gwbridge deveria ser aceito")
	}
	if softphone.allowsMediaIP(net.ParseIP("10.10.25.13")) {
		t.Error("IP da overlay deveria ser recusado")
	}
}

// Instalação de nó único, sem overlay, não deveria precisar configurar nada.
func TestMediaSubnetAusenteMantemTodasAsInterfaces(t *testing.T) {
	t.Setenv("SOFTPHONE_TOKEN_SECRET", testMediaSecret)
	t.Setenv("SOFTPHONE_MEDIA_SUBNET", "")
	restoreSoftphoneConfig(t)
	loadSoftphoneConfig()

	for _, ip := range []string{"172.18.0.4", "10.10.25.13", "192.168.1.7"} {
		if !softphone.allowsMediaIP(net.ParseIP(ip)) {
			t.Errorf("sem sub-rede configurada, %s deveria ser aceito", ip)
		}
	}
}

// CIDR inválido não pode deixar a mídia sem nenhuma interface: isso transformaria um erro de
// digitação em chamada muda, que é o modo de falha mais caro de diagnosticar desta feature.
func TestMediaSubnetInvalidaNaoDerrubaAMidia(t *testing.T) {
	t.Setenv("SOFTPHONE_TOKEN_SECRET", testMediaSecret)
	t.Setenv("SOFTPHONE_MEDIA_SUBNET", "172.18.0.0/nao-e-cidr")
	restoreSoftphoneConfig(t)
	loadSoftphoneConfig()

	if !softphone.allowsMediaIP(net.ParseIP("10.10.25.13")) {
		t.Error("CIDR inválido deveria cair no comportamento de aceitar todas")
	}
}
