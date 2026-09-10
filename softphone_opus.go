package main

/*
#cgo pkg-config: opus
#include <opus.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"wuzapi/internal/meowcaller"
)

// Adaptador de codec da perna do navegador (feature 021, research §R3).
//
// A perna do WhatsApp **não** é Opus: o meowcaller fala MLow, em Go puro. A perna do
// navegador é Opus, porque é o que o WebRTC negocia. Este arquivo é a tradução entre as
// duas, e o ponto de encontro é o formato interno da biblioteca — float32 mono, 16 kHz.
//
// **Por que um wrapper direto e não uma biblioteca de terceiros**: as ligações Go
// conhecidas para o Opus vinculam também o `libopusfile`, que serve para ler arquivos Ogg —
// coisa que não fazemos aqui. Precisamos de quatro funções do `libopus`, e escrevê-las
// diretamente mantém a imagem com uma dependência nativa em vez de duas.
//
// **Por que nenhum reamostrador aparece aqui**: o libopus aceita criar codificador e
// decodificador diretamente a 16 kHz, e a taxa do fluxo na rede é independente da taxa da
// API. O navegador manda Opus a 48 kHz e o decodificador entrega 16 kHz mono sem que
// precisemos escrever uma linha de conversão — que seria justamente o tipo de código difícil
// de acertar e fácil de deixar com um artefato audível.

// opusMaxPacketBytes é o teto de um pacote codificado. Fala a 16 kHz mono fica em algumas
// centenas de bytes; a folga cobre o pior caso sem alocar por quadro.
const opusMaxPacketBytes = 4000

// opusMaxFrameSamples é o maior quadro que o decodificador pode produzir: 120 ms a 16 kHz.
// Dimensiona o buffer de saída, e não o que esperamos receber.
const opusMaxFrameSamples = meowcaller.SampleRate / 1000 * 120

// validEncodeFrameSizes são os tamanhos de quadro que o Opus aceita a 16 kHz —
// 2,5 / 5 / 10 / 20 / 40 / 60 ms. Recusar cedo evita um pacote malformado no meio da
// conversa, que é muito mais difícil de diagnosticar do que um erro na borda.
var validEncodeFrameSizes = map[int]bool{40: true, 80: true, 160: true, 320: true, 640: true, 960: true}

var errOpusClosed = errors.New("softphone: opus codec is closed")

// opusEncoder codifica PCM de 16 kHz mono para pacotes Opus, rumo ao navegador.
type opusEncoder struct {
	enc *C.OpusEncoder
	buf []byte
}

// newOpusEncoder cria o codificador em modo VOIP.
//
// OPUS_APPLICATION_VOIP, e não AUDIO: otimiza para inteligibilidade da fala em vez de
// fidelidade musical, que é exatamente o compromisso certo numa ligação.
func newOpusEncoder() (*opusEncoder, error) {
	var cerr C.int
	enc := C.opus_encoder_create(
		C.opus_int32(meowcaller.SampleRate),
		1,
		C.OPUS_APPLICATION_VOIP,
		&cerr,
	)
	if cerr != C.OPUS_OK {
		return nil, fmt.Errorf("softphone: opus_encoder_create: %s", opusStrError(cerr))
	}
	return &opusEncoder{enc: enc, buf: make([]byte, opusMaxPacketBytes)}, nil
}

// Encode codifica um quadro de 60 ms — o quadro nativo do meowcaller.
func (e *opusEncoder) Encode(pcm []float32) ([]byte, error) {
	return e.EncodeFrame(pcm)
}

// EncodeFrame codifica qualquer tamanho de quadro válido a 16 kHz.
func (e *opusEncoder) EncodeFrame(pcm []float32) ([]byte, error) {
	if e.enc == nil {
		return nil, errOpusClosed
	}
	if !validEncodeFrameSizes[len(pcm)] {
		return nil, fmt.Errorf(
			"softphone: invalid opus frame size %d at %d Hz", len(pcm), meowcaller.SampleRate)
	}

	n := C.opus_encode_float(
		e.enc,
		(*C.float)(unsafe.Pointer(&pcm[0])),
		C.int(len(pcm)),
		(*C.uchar)(unsafe.Pointer(&e.buf[0])),
		C.opus_int32(len(e.buf)),
	)
	if n < 0 {
		return nil, fmt.Errorf("softphone: opus_encode_float: %s", opusStrError(C.int(n)))
	}

	// Cópia deliberada: `buf` é reaproveitado a cada quadro, e devolver a fatia interna
	// entregaria ao chamador um buffer que muda debaixo dele no quadro seguinte.
	packet := make([]byte, int(n))
	copy(packet, e.buf[:n])
	return packet, nil
}

// Close libera o codificador. Seguro chamar mais de uma vez.
func (e *opusEncoder) Close() {
	if e.enc != nil {
		C.opus_encoder_destroy(e.enc)
		e.enc = nil
	}
}

// opusDecoder decodifica pacotes Opus do navegador para PCM de 16 kHz mono.
type opusDecoder struct {
	dec *C.OpusDecoder
	buf []float32
}

func newOpusDecoder() (*opusDecoder, error) {
	var cerr C.int
	dec := C.opus_decoder_create(C.opus_int32(meowcaller.SampleRate), 1, &cerr)
	if cerr != C.OPUS_OK {
		return nil, fmt.Errorf("softphone: opus_decoder_create: %s", opusStrError(cerr))
	}
	return &opusDecoder{dec: dec, buf: make([]float32, opusMaxFrameSamples)}, nil
}

// Decode devolve as amostras de um pacote.
//
// O tamanho da saída acompanha o pacote, e não o nosso quadro: o Chrome envia 20 ms, que
// aqui vira 320 amostras. Quem agrupa até o quadro de 60 ms do meowcaller é a ponte.
func (d *opusDecoder) Decode(packet []byte) ([]float32, error) {
	if d.dec == nil {
		return nil, errOpusClosed
	}
	if len(packet) == 0 {
		// Pacote vazio significaria "perda" para o libopus, que produziria ocultação de
		// perda. Não é o que queremos: a ocultação é do NetEq do navegador, e inventar
		// áudio aqui mascararia um problema de transporte.
		return nil, errors.New("softphone: empty opus packet")
	}

	n := C.opus_decode_float(
		d.dec,
		(*C.uchar)(unsafe.Pointer(&packet[0])),
		C.opus_int32(len(packet)),
		(*C.float)(unsafe.Pointer(&d.buf[0])),
		C.int(len(d.buf)),
		0,
	)
	if n < 0 {
		return nil, fmt.Errorf("softphone: opus_decode_float: %s", opusStrError(C.int(n)))
	}

	samples := make([]float32, int(n))
	copy(samples, d.buf[:n])
	return samples, nil
}

// Close libera o decodificador. Seguro chamar mais de uma vez.
func (d *opusDecoder) Close() {
	if d.dec != nil {
		C.opus_decoder_destroy(d.dec)
		d.dec = nil
	}
}

// opusStrError traduz o código de erro do libopus.
func opusStrError(code C.int) string {
	return C.GoString(C.opus_strerror(code))
}
