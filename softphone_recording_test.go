package main

import (
	"os"
	"path/filepath"
	"testing"

	"wuzapi/internal/meowcaller"
)

// Gravação da conversa ao vivo (US9, FR-048 a FR-052).
//
// A feature não inventa regra nova: cota diária, limite de duração, truncamento, link
// assinado e retenção são exatamente os da `020` (FR-050). O que muda é o **conteúdo** da
// perna local — deixa de ser o arquivo reproduzido e passa a ser a voz do atendente.
//
// Duas exigências carregam esta story:
//
//  1. as duas vozes precisam estar no arquivo (US9-AS2);
//  2. o trecho silenciado precisa refletir o que o contato de fato ouviu (US9-AS7).

/** readWAVSamples lê as amostras de um WAV de 16 bits, pulando o cabeçalho de 44 bytes. */
func readWAVSamples(t *testing.T, path string) []int16 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("não foi possível ler %s: %v", path, err)
	}
	if len(raw) <= 44 {
		return nil
	}
	body := raw[44:]
	samples := make([]int16, 0, len(body)/2)
	for i := 0; i+1 < len(body); i += 2 {
		samples = append(samples, int16(body[i])|int16(body[i+1])<<8)
	}
	return samples
}

func hasAudibleSample(samples []int16) bool {
	for _, sample := range samples {
		if sample != 0 {
			return true
		}
	}
	return false
}

// research §R6: a voz do contato precisa alcançar dois consumidores ao mesmo tempo.
//
// `Call.Receive` **substitui** em vez de somar, e o gravador já ocupa o slot. Sem o tee,
// conceder gravação silenciaria o atendente — o modo de falha mais cruel possível, porque só
// apareceria nas chamadas gravadas.
func TestRecorderTeeSinkFeedsBothConsumers(t *testing.T) {
	recorder, err := newCallRecorder("inst_tee", "call_1")
	if err != nil {
		t.Fatalf("newCallRecorder() = %v", err)
	}
	defer recorder.Discard()

	var extra int
	sink := recorder.TeeSink(meowcaller.SinkFunc(func([]float32) { extra++ }))

	frame := make([]float32, meowcaller.FrameSamples)
	for i := range frame {
		frame[i] = 0.5
	}
	_ = sink.WriteFrame(frame)
	_ = sink.WriteFrame(frame)

	if extra != 2 {
		t.Errorf("consumidor extra recebeu %d quadros, esperado 2", extra)
	}

	result := recorder.Close()
	if !hasAudibleSample(readWAVSamples(t, result.RemotePath)) {
		t.Error("a perna remota ficou vazia; o gravador perdeu a voz do contato")
	}
}

// Sem consumidor extra, o tee se comporta como o sink comum: uma chamada gravada **sem**
// atendente — o caminho automatizado da `020` — não pode mudar de comportamento.
func TestRecorderTeeSinkWithoutExtraBehavesLikeSink(t *testing.T) {
	recorder, err := newCallRecorder("inst_tee2", "call_1")
	if err != nil {
		t.Fatalf("newCallRecorder() = %v", err)
	}
	defer recorder.Discard()

	sink := recorder.TeeSink(nil)
	frame := make([]float32, meowcaller.FrameSamples)
	for i := range frame {
		frame[i] = 0.25
	}
	_ = sink.WriteFrame(frame)

	result := recorder.Close()
	if !hasAudibleSample(readWAVSamples(t, result.RemotePath)) {
		t.Error("a perna remota ficou vazia sem consumidor extra")
	}
}

// US9-AS2 e US9-AS7, juntas — porque é a combinação que importa.
//
// A perna local é a voz do atendente, e o trecho silenciado precisa sair **em silêncio**: a
// gravação tem de refletir o que o contato de fato ouviu, não o que o microfone captou. Se a
// pausa aparecesse gravada, o arquivo entregaria a conversa particular que o atendente
// silenciou para ter.
func TestRecordingCapturesAgentVoiceAndRespectsMute(t *testing.T) {
	recorder, err := newCallRecorder("inst_rec", "call_1")
	if err != nil {
		t.Fatalf("newCallRecorder() = %v", err)
	}
	defer recorder.Discard()

	bridge := newLiveAudioBridge()
	defer bridge.Close()

	// A fonte é a ponte, derivada para o gravador — exatamente como `liveCall.play` monta.
	source := recorder.WrapSource(bridge)
	sink := recorder.TeeSink(nil)

	speak := func() []float32 {
		frame := make([]float32, meowcaller.FrameSamples)
		for i := range frame {
			frame[i] = 0.4
		}
		return frame
	}

	// Trecho 1: o atendente fala.
	bridge.PushMic(speak())
	if _, err := source.ReadFrame(); err != nil {
		t.Fatalf("ReadFrame() = %v", err)
	}
	_ = sink.WriteFrame(speak()) // o contato também fala; avança o relógio da gravação

	// Trecho 2: o atendente silencia e continua falando com um colega.
	bridge.SetMuted(true)
	bridge.PushMic(speak())
	if _, err := source.ReadFrame(); err != nil {
		t.Fatalf("ReadFrame() = %v", err)
	}
	_ = sink.WriteFrame(speak())

	result := recorder.Close()

	local := readWAVSamples(t, result.LocalPath)
	remote := readWAVSamples(t, result.RemotePath)

	if len(local) != len(remote) {
		t.Errorf("trilhas com comprimentos diferentes: local=%d remoto=%d — a mixagem sairia dessincronizada",
			len(local), len(remote))
	}
	if !hasAudibleSample(local[:meowcaller.FrameSamples]) {
		t.Error("o primeiro trecho não contém a voz do atendente (US9-AS2)")
	}
	if hasAudibleSample(local[meowcaller.FrameSamples:]) {
		t.Error("o trecho silenciado contém a voz do atendente (US9-AS7, FR-049)")
	}
}

// FR-052 e US9-AS6: sem gravação solicitada, nenhum áudio é retido.
//
// A verificação é do disco, e não do código: o que a spec proíbe é o arquivo existir, e um
// teste que apenas confirmasse que `newCallRecorder` não foi chamado passaria mesmo que
// alguém escrevesse o áudio em outro lugar.
func TestNoRecorderMeansNoAudioOnDisk(t *testing.T) {
	before := countCallRecordingDirs(t)

	bridge := newLiveAudioBridge()
	defer bridge.Close()

	// Uma conversa inteira sem gravador: nada é derivado, nada é escrito.
	frame := make([]float32, meowcaller.FrameSamples)
	for i := range frame {
		frame[i] = 0.4
	}
	for range 10 {
		bridge.PushMic(frame)
		if _, err := bridge.ReadFrame(); err != nil {
			t.Fatalf("ReadFrame() = %v", err)
		}
		_ = bridge.WriteFrame(frame)
	}

	if after := countCallRecordingDirs(t); after != before {
		t.Errorf("diretórios de gravação = %d, esperado %d — áudio retido sem solicitação (FR-052)",
			after, before)
	}
}

/** countCallRecordingDirs conta os diretórios temporários de gravação de chamada. */
func countCallRecordingDirs(t *testing.T) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "call-*"))
	if err != nil {
		t.Fatalf("glob = %v", err)
	}
	return len(matches)
}
