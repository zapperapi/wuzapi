package main

import (
	"testing"

	"wuzapi/internal/meowcaller"
)

// Silenciar o microfone (US6, FR-026 a FR-028).
//
// É o controle mais usado de qualquer operação de atendimento por voz, e o requisito tem uma
// exigência forte: **nada** do atendente pode trafegar enquanto o microfone está silenciado
// (FR-027). Não "quase nada", não "com atraso": nada.
//
// A garantia é do servidor, e não do navegador. Confiar no `track.enabled = false` deixaria
// FR-027 nas mãos de código que roda em território não confiável.

/** frameHasSound diz se um quadro contém alguma amostra diferente de silêncio. */
func frameHasSound(frame []float32) bool {
	for _, sample := range frame {
		if sample != 0 {
			return true
		}
	}
	return false
}

/** speech devolve um quadro cheio de amostras audíveis. */
func speech() []float32 {
	frame := make([]float32, meowcaller.FrameSamples)
	for i := range frame {
		frame[i] = 0.42
	}
	return frame
}

func TestBridgeMutedEmitsSilence(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	b.SetMuted(true)
	b.PushMic(speech())

	frame, err := b.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() = %v", err)
	}
	if frameHasSound(frame) {
		t.Error("quadro contém áudio com o microfone silenciado (FR-027)")
	}
}

// O caso que decide o desenho: o atendente silencia, conversa com um colega, e reativa.
//
// Nada do que foi dito durante o silêncio pode alcançar o contato — nem naquele instante,
// nem depois. Guardar as amostras numa fila para "não perder áudio" transformaria a pausa
// numa gravação com atraso, e entregaria ao contato exatamente a conversa particular que o
// atendente silenciou para ter.
func TestBridgeDiscardsAudioCapturedWhileMuted(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	b.SetMuted(true)
	// Conversa particular, capturada pelo microfone que ainda está aberto no navegador.
	for range bridgeMaxQueuedFrames * 2 {
		b.PushMic(speech())
	}

	b.SetMuted(false)

	// O primeiro quadro após reativar precisa ser silêncio: não há nada legítimo a enviar.
	frame, _ := b.ReadFrame()
	if frameHasSound(frame) {
		t.Fatal("áudio capturado durante o silenciamento vazou após reativar (FR-027)")
	}
}

func TestBridgeUnmutedResumesAudio(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	b.SetMuted(true)
	b.PushMic(speech())
	b.SetMuted(false)

	// Fala nova, depois de reativar: essa precisa chegar.
	b.PushMic(speech())

	frame, _ := b.ReadFrame()
	if !frameHasSound(frame) {
		t.Error("a voz do atendente não voltou após reativar (US6-AS3)")
	}
}

func TestBridgeMutedState(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	if b.Muted() {
		t.Error("a ponte deveria nascer com o microfone ativo (FR-028)")
	}
	b.SetMuted(true)
	if !b.Muted() {
		t.Error("SetMuted(true) não refletiu no estado")
	}
	b.SetMuted(false)
	if b.Muted() {
		t.Error("SetMuted(false) não refletiu no estado")
	}
}

// FR-026 e US6-AS2: silenciar não toca na chamada nem no caminho de descida. O contato
// continua sendo ouvido pelo atendente enquanto ele está mudo — é para isso que ele silencia.
func TestBridgeMutedStillDeliversContactAudio(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	var received int
	b.SetPeerSink(func([]float32) { received++ })

	b.SetMuted(true)
	_ = b.WriteFrame(speech())
	_ = b.WriteFrame(speech())

	if received != 2 {
		t.Errorf("quadros do contato entregues = %d, esperado 2 (US6-AS2)", received)
	}
}

// `Reset` descarta áudio pendente e **preserva** o silenciamento.
//
// A distinção é sutil e importa: `Reset` é chamado nos dois casos, e eles querem coisas
// opostas. Numa **reconexão** dentro do período de graça, o atendente continua na mesma
// conversa — reativar o microfone dele sozinho, sem que ninguém pedisse, colocaria no ar
// uma conversa particular. Numa **chamada nova**, o microfone precisa começar ativo
// (FR-028), e quem zera é a anexação à chamada, que sabe que é um começo.
func TestBridgeResetPreservesMuteForReconnection(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	b.SetMuted(true)
	b.Reset()

	if !b.Muted() {
		t.Error("Reset() reativou o microfone; numa reconexão isso colocaria no ar uma conversa particular")
	}
}
