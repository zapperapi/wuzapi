package main

import "testing"

// Reconectar dentro do período de graça substitui a sessão WebRTC mantendo a mesma ponte
// (FR-038, e o comentário do campo `media` em agentSession diz isso explicitamente).
//
// A mídia nova se apresenta à ponte antes de a antiga ser fechada, e o `Close` da antiga
// desarma o caminho de volta que a nova acabou de armar. O resultado é assimétrico e mudo:
// o contato continua ouvindo o atendente, porque essa perna passa pela fila da ponte, e o
// atendente para de ouvir o contato para sempre — sem erro, sem log, sem sintoma além do
// silêncio.
func TestTrocaDeMidiaMantemOCaminhoDeVoltaArmado(t *testing.T) {
	bridge := newLiveAudioBridge()
	session := &agentSession{bridge: bridge}

	session.setMedia(&softphoneMedia{bridge: bridge})
	session.setMedia(&softphoneMedia{bridge: bridge})

	bridge.mu.Lock()
	armed := bridge.peerSink != nil
	bridge.mu.Unlock()

	if !armed {
		t.Fatal("depois da troca de mídia a voz do contato não tem para onde ir")
	}
}
