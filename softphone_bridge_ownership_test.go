package main

import "testing"

// A ponte pertence à **sessão** e é compartilhada por todas as mídias dela. O `Close` de uma
// mídia não pode desarmá-la: quando ele o faz, fechar uma mídia velha — ou uma recém-criada
// que falhou no meio da negociação e se fecha nos próprios caminhos de erro — deixa muda a
// mídia viva que estava servindo. Em produção isso apareceu como "a primeira chamada tem
// áudio, a segunda não", e o único rastro era a ausência de rastro.
func TestFecharMidiaVelhaNaoDesarmaAPonteDaAtual(t *testing.T) {
	bridge := newLiveAudioBridge()
	session := &agentSession{bridge: bridge}

	atual := &softphoneMedia{bridge: bridge}
	session.setMedia(atual)

	velha := &softphoneMedia{bridge: bridge}
	velha.Close()

	bridge.mu.Lock()
	armada := bridge.peerSink != nil
	bridge.mu.Unlock()

	if !armada {
		t.Fatal("fechar outra mídia desarmou a ponte da mídia corrente")
	}
}

// Quando a conexão cai, a mídia vai embora e a ponte precisa **mesmo** parar de entregar:
// sem destino vivo, o áudio do contato tem de ser descartado até a renegociação. Quem
// responde por isso é a sessão, que é dona da ponte — não o `Close` da mídia.
func TestFecharAMidiaDaSessaoDesarmaAPonte(t *testing.T) {
	bridge := newLiveAudioBridge()
	session := &agentSession{bridge: bridge}
	session.setMedia(&softphoneMedia{bridge: bridge})

	session.closeMediaOnly()

	bridge.mu.Lock()
	armada := bridge.peerSink != nil
	bridge.mu.Unlock()

	if armada {
		t.Fatal("a ponte continuou entregando para uma mídia que não existe mais")
	}
}
