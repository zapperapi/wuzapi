package main

import (
	"os"
	"path/filepath"
	"testing"
)

// O engine do meowcaller já emite diagnóstico por pacote — RTP de entrada, autenticação
// SRTP, áudio decodificado com RMS — mas o gravador nunca foi ligado no wuzapi, então tudo
// isso caía em um `*diag.Recorder` nulo. Sem ele, "a mídia do contato não chega" e "chega e
// é descartada em silêncio" são indistinguíveis por log.
func TestDiagDesligadoPorPadrao(t *testing.T) {
	if rec := newSoftphoneDiagRecorder("", "inst_1"); rec != nil {
		t.Fatal("sem SOFTPHONE_DIAG_DIR não deveria haver gravador")
	}
}

// Um gravador por instância, em diretório próprio: dois clientes no mesmo processo não podem
// escrever no mesmo arquivo, senão a captura de uma chamada vem embaralhada com a de outra.
func TestDiagGravaPorInstancia(t *testing.T) {
	base := t.TempDir()

	rec := newSoftphoneDiagRecorder(base, "inst_1")
	if rec == nil {
		t.Fatal("com SOFTPHONE_DIAG_DIR definido deveria haver gravador")
	}
	rec.Emit("rtp", map[string]any{"event": "in", "ssrc": 42})

	arquivo := filepath.Join(base, "inst_1", "rtp.jsonl")
	if _, err := os.Stat(arquivo); err != nil {
		t.Fatalf("esperava %s: %v", arquivo, err)
	}
}
