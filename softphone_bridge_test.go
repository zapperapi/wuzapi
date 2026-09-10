package main

import (
	"testing"
	"time"

	"wuzapi/internal/meowcaller"
)

// A ponte de áudio é o objeto mais sensível a tempo da feature: `ReadFrame` é chamado pelo
// laço de mídia do meowcaller a cada 60 ms, e o que ele devolver é o que o contato ouve.
//
// Duas propriedades importam mais que qualquer outra, e são o que estes testes cobrem:
//
//  1. **Nunca bloquear.** Bloquear ali atrasa o fluxo para o contato e, pior, atrasa o
//     próximo quadro — o atraso não se recupera, ele acumula.
//  2. **Silêncio no esvaziamento.** Rede oscilando é o estado normal; devolver menos de um
//     quadro cheio corromperia o encoder, e devolver erro derrubaria a chamada.

func TestBridgeReadFrameReturnsFullFrame(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	b.PushMic(make([]float32, meowcaller.FrameSamples))

	frame, err := b.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() erro = %v", err)
	}
	if len(frame) != meowcaller.FrameSamples {
		t.Errorf("len(frame) = %d, esperado %d", len(frame), meowcaller.FrameSamples)
	}
}

func TestBridgeReadFrameYieldsSilenceWhenStarved(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	frame, err := b.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() sem áudio deveria devolver silêncio, e devolveu erro = %v", err)
	}
	if len(frame) != meowcaller.FrameSamples {
		t.Fatalf("len(frame) = %d, esperado %d", len(frame), meowcaller.FrameSamples)
	}
	for i, sample := range frame {
		if sample != 0 {
			t.Fatalf("frame[%d] = %v, esperado 0 (silêncio)", i, sample)
		}
	}
}

// Quadro parcial na fila também é silêncio: meio quadro entregue ao encoder produz um
// artefato audível, e é pior do que um instante de silêncio.
func TestBridgeReadFrameYieldsSilenceOnPartialFrame(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	partial := make([]float32, meowcaller.FrameSamples/2)
	for i := range partial {
		partial[i] = 0.5
	}
	b.PushMic(partial)

	frame, _ := b.ReadFrame()
	for i, sample := range frame {
		if sample != 0 {
			t.Fatalf("frame[%d] = %v, esperado silêncio enquanto o quadro não completa", i, sample)
		}
	}

	// Completado o quadro, o áudio sai — inclusive a metade que já estava na fila.
	b.PushMic(make([]float32, meowcaller.FrameSamples/2))
	frame, _ = b.ReadFrame()
	if frame[0] != 0.5 {
		t.Errorf("frame[0] = %v, esperado 0.5 — a metade pendente deveria ter sido preservada", frame[0])
	}
}

func TestBridgeReadFrameNeverBlocks(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			if _, err := b.ReadFrame(); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReadFrame bloqueou: 100 leituras sem áudio deveriam ser instantâneas")
	}
}

// A fila é limitada de propósito. Sem limite, uma rajada do navegador — ou um laço de mídia
// momentaneamente lento — acumularia áudio que só seria reproduzido segundos depois, e a
// conversa ficaria progressivamente mais atrasada sem nunca se recuperar. Descartar o mais
// antigo troca um engasgo por atraso permanente, que é a troca certa numa conversa ao vivo.
func TestBridgeDropsOldestWhenBacklogged(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	for i := range bridgeMaxQueuedFrames + 10 {
		frame := make([]float32, meowcaller.FrameSamples)
		for j := range frame {
			frame[j] = float32(i)
		}
		b.PushMic(frame)
	}

	frame, _ := b.ReadFrame()
	if frame[0] == 0 {
		t.Fatal("a leitura devolveu o quadro mais antigo; os antigos deveriam ter sido descartados")
	}
	if int(frame[0]) < 10 {
		t.Errorf("frame[0] = %v; esperado um quadro recente, não o começo da rajada", frame[0])
	}
}

// A voz do contato precisa alcançar dois consumidores ao mesmo tempo quando há gravação
// (research §R6). A ponte é um deles; o gravador é o outro. Trocar o destino a quente é o
// que permite reconectar sem derrubar a chamada (FR-038).
func TestBridgePeerSinkIsHotSwappable(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	var first, second int
	b.SetPeerSink(func([]float32) { first++ })
	_ = b.WriteFrame(make([]float32, meowcaller.FrameSamples))

	b.SetPeerSink(func([]float32) { second++ })
	_ = b.WriteFrame(make([]float32, meowcaller.FrameSamples))

	if first != 1 {
		t.Errorf("primeiro destino recebeu %d quadros, esperado 1", first)
	}
	if second != 1 {
		t.Errorf("segundo destino recebeu %d quadros, esperado 1", second)
	}
}

// Sem destino ligado, escrever não pode falhar: durante o período de graça a sessão não tem
// para onde mandar o áudio do contato, e a chamada precisa continuar viva assim mesmo.
func TestBridgeWriteFrameWithoutSinkIsHarmless(t *testing.T) {
	b := newLiveAudioBridge()
	defer b.Close()

	if err := b.WriteFrame(make([]float32, meowcaller.FrameSamples)); err != nil {
		t.Errorf("WriteFrame() sem destino = %v, esperado nil", err)
	}
}

// Depois de fechada, a ponte devolve io.EOF para o laço de mídia parar de puxar.
func TestBridgeClosedSourceStops(t *testing.T) {
	b := newLiveAudioBridge()
	b.Close()

	if _, err := b.ReadFrame(); err == nil {
		t.Error("ReadFrame() após Close() deveria devolver erro")
	}
	// Fechar duas vezes é seguro: o contrato de AudioSource exige isso.
	b.Close()
}
