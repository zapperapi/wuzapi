package meowcaller

import (
	"bytes"
	"testing"

	waBinary "github.com/polymorfa/hypermeow/binary"

	"wuzapi/internal/meowcaller/stun"
)

// O `<relay>` de uma chamada 1:1 nomeia o par com um pid — `peer_pid="1"` ao lado de
// `self_pid="2"` — exatamente como faz numa chamada de grupo. Hoje esse número é usado só
// para localizar o JID do participante e descartado em seguida, então o allocate declara
// apenas os nossos streams e nunca assina os do contato.
func TestParseRelayDataGuardaOPidDoPar(t *testing.T) {
	peer := peerJID()
	relay := &waBinary.Node{
		Tag:   "relay",
		Attrs: waBinary.Attrs{"peer_pid": "1", "self_pid": "2"},
		Content: []waBinary.Node{
			{Tag: "participant", Attrs: waBinary.Attrs{"pid": "1", "jid": peer}},
		},
	}

	rd := parseRelayData(relay)

	if !rd.hasPeerPID {
		t.Fatal("pid do par não foi registrado")
	}
	if rd.peerPID != 1 {
		t.Fatalf("peerPID = %d, want 1", rd.peerPID)
	}
}

// Pid zero é válido — o `<participant pid="0">` aparece em ofertas reais —, então a
// ausência precisa de sinalizador próprio em vez de ser inferida do valor.
func TestParseRelayDataSemPeerPidNaoInventaZero(t *testing.T) {
	relay := &waBinary.Node{Tag: "relay", Attrs: waBinary.Attrs{"self_pid": "2"}}

	rd := parseRelayData(relay)

	if rd.hasPeerPID {
		t.Fatal("sem `peer_pid` no nó, nada deveria ser registrado")
	}
}

// Com o par identificado, o allocate tem de carregar a assinatura dos fluxos dele — é o que
// diz ao relay para onde encaminhar a mídia do contato. Sem isso o relay mantém o caminho
// vivo com ping e nunca envia áudio, que é o sintoma em produção.
func TestAllocateAssinaOsFluxosDoPar(t *testing.T) {
	var tx [12]byte
	token := []byte("token-de-relay")
	key := []byte("chave-de-integridade")
	var endpointXor [6]byte
	streamSsrcs := [9]uint32{1, 2, 3, 4, 5, 6, 7, 8, 9}
	const appDataSSRC uint32 = 4242

	rd := &relayData{relayKeyASCII: key, peerPID: 1, hasPeerPID: true}

	got := buildCallAllocate(tx, token, endpointXor, streamSsrcs, appDataSSRC, rd)
	want := stun.BuildWasmStunAllocateRequestWithGroupSubscriptions(
		tx, token, endpointXor, streamSsrcs, appDataSSRC, []uint32{1}, key,
	)

	if !bytes.Equal(got, want) {
		t.Fatalf("allocate sem as assinaturas do par (%d bytes, esperado %d)", len(got), len(want))
	}
}

// Sem par identificado, nada muda: o allocate continua sendo o de sempre.
func TestAllocateSemParSegueSemAssinatura(t *testing.T) {
	var tx [12]byte
	token := []byte("token-de-relay")
	key := []byte("chave-de-integridade")
	var endpointXor [6]byte
	streamSsrcs := [9]uint32{1, 2, 3, 4, 5, 6, 7, 8, 9}

	rd := &relayData{relayKeyASCII: key}

	got := buildCallAllocate(tx, token, endpointXor, streamSsrcs, 4242, rd)
	want := stun.BuildWasmStunAllocateRequestWithStreamSsrcs(tx, token, endpointXor, streamSsrcs, key)

	if !bytes.Equal(got, want) {
		t.Fatal("allocate mudou para uma chamada sem pid de par")
	}
}
