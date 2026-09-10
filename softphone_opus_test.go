package main

import (
	"math"
	"testing"

	"wuzapi/internal/meowcaller"
)

// O adaptador de codec é a fronteira entre as duas pernas da chamada: Opus do lado do
// navegador, MLow do lado do WhatsApp, e PCM float32 de 16 kHz no meio (research §R3).
//
// Não se testa fidelidade de codec aqui — isso é trabalho do libopus, e refazê-lo seria
// desconfiar da biblioteca errada. O que se testa é o que **nós** podemos errar: comprimento
// de quadro, taxa de amostragem e o que acontece com um pacote corrompido.

func TestOpusRoundTripPreservesFrameLength(t *testing.T) {
	enc, err := newOpusEncoder()
	if err != nil {
		t.Fatalf("newOpusEncoder() = %v", err)
	}
	defer enc.Close()

	dec, err := newOpusDecoder()
	if err != nil {
		t.Fatalf("newOpusDecoder() = %v", err)
	}
	defer dec.Close()

	// Senoide de 440 Hz: sinal real o bastante para o encoder não tratar como silêncio, que
	// é comprimido a quase nada e esconderia erro de enquadramento.
	pcm := make([]float32, meowcaller.FrameSamples)
	for i := range pcm {
		pcm[i] = float32(0.3 * math.Sin(2*math.Pi*440*float64(i)/meowcaller.SampleRate))
	}

	packet, err := enc.Encode(pcm)
	if err != nil {
		t.Fatalf("Encode() = %v", err)
	}
	if len(packet) == 0 {
		t.Fatal("Encode() devolveu pacote vazio")
	}

	decoded, err := dec.Decode(packet)
	if err != nil {
		t.Fatalf("Decode() = %v", err)
	}
	if len(decoded) != meowcaller.FrameSamples {
		t.Errorf("len(decoded) = %d, esperado %d — um quadro de 60 ms a 16 kHz",
			len(decoded), meowcaller.FrameSamples)
	}
}

// Quadro de 20 ms é o que o Chrome envia por padrão. O decodificador precisa aceitá-lo e
// devolver 320 amostras, para a ponte agrupar de três em três até o quadro de 60 ms.
func TestOpusDecodeAcceptsTwentyMillisecondPackets(t *testing.T) {
	enc, err := newOpusEncoder()
	if err != nil {
		t.Fatalf("newOpusEncoder() = %v", err)
	}
	defer enc.Close()
	dec, err := newOpusDecoder()
	if err != nil {
		t.Fatalf("newOpusDecoder() = %v", err)
	}
	defer dec.Close()

	const twentyMs = meowcaller.SampleRate / 50 // 320 amostras
	packet, err := enc.EncodeFrame(make([]float32, twentyMs))
	if err != nil {
		t.Fatalf("EncodeFrame(20ms) = %v", err)
	}

	decoded, err := dec.Decode(packet)
	if err != nil {
		t.Fatalf("Decode() = %v", err)
	}
	if len(decoded) != twentyMs {
		t.Errorf("len(decoded) = %d, esperado %d", len(decoded), twentyMs)
	}
}

// Pacote corrompido não pode derrubar a sessão. Rede real entrega lixo de vez em quando, e
// uma chamada que cai por causa de um pacote é uma chamada que cai.
func TestOpusDecodeRejectsGarbageWithoutPanicking(t *testing.T) {
	dec, err := newOpusDecoder()
	if err != nil {
		t.Fatalf("newOpusDecoder() = %v", err)
	}
	defer dec.Close()

	if _, err := dec.Decode([]byte{0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Error("Decode() de lixo deveria devolver erro")
	}
	if _, err := dec.Decode(nil); err == nil {
		t.Error("Decode() de pacote vazio deveria devolver erro")
	}

	// E o decodificador continua utilizável depois disso.
	enc, err := newOpusEncoder()
	if err != nil {
		t.Fatalf("newOpusEncoder() = %v", err)
	}
	defer enc.Close()
	packet, err := enc.Encode(make([]float32, meowcaller.FrameSamples))
	if err != nil {
		t.Fatalf("Encode() = %v", err)
	}
	if _, err := dec.Decode(packet); err != nil {
		t.Errorf("Decode() após lixo = %v, esperado nil", err)
	}
}

// Comprimento inválido é erro nosso, não do codec: só os tamanhos de quadro que o Opus
// aceita a 16 kHz podem ser codificados, e falhar cedo evita um pacote silenciosamente
// malformado no meio da conversa.
func TestOpusEncodeRejectsInvalidFrameLength(t *testing.T) {
	enc, err := newOpusEncoder()
	if err != nil {
		t.Fatalf("newOpusEncoder() = %v", err)
	}
	defer enc.Close()

	if _, err := enc.Encode(make([]float32, 123)); err == nil {
		t.Error("Encode() com comprimento inválido deveria devolver erro")
	}
}

func TestOpusCloseIsIdempotent(t *testing.T) {
	enc, err := newOpusEncoder()
	if err != nil {
		t.Fatalf("newOpusEncoder() = %v", err)
	}
	enc.Close()
	enc.Close()

	dec, err := newOpusDecoder()
	if err != nil {
		t.Fatalf("newOpusDecoder() = %v", err)
	}
	dec.Close()
	dec.Close()
}
