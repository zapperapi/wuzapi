package main

import (
	"fmt"
	"io"
	"runtime/debug"
	"sync"

	"github.com/rs/zerolog/log"

	"wuzapi/internal/meowcaller"
)

// Ponte de áudio entre o navegador e a chamada (feature 021, research §R4).
//
// É, ao mesmo tempo, o `AudioSource` que o meowcaller puxa para mandar ao contato e o
// destino do `AudioSink` que traz a voz do contato de volta. O que a torna interessante é o
// que ela **não** é: ela não é a sessão WebRTC.
//
// **Por que o objeto é estável e a sessão por trás é que troca.** FR-038 exige que uma
// reconexão dentro do período de graça retome *a mesma chamada, com o mesmo identificador*.
// Se a ponte fosse a sessão WebRTC, reconectar significaria trocar o `AudioSource` da
// chamada e torcer para que a contabilidade do `liveCall` acompanhasse. Sendo estável,
// reconectar é reapontar um ponteiro interno: a chamada, o `Player` e o gravador não
// percebem nada. Durante a janela sem sessão a ponte devolve silêncio — que é exatamente o
// que FR-037 descreve.

// bridgeMaxQueuedFrames limita o acúmulo de áudio do microfone.
//
// Cinco quadros são 300 ms. Sem limite, uma rajada do navegador acumularia áudio que só
// seria reproduzido segundos depois, e a conversa ficaria progressivamente mais atrasada sem
// nunca se recuperar. Descartar o mais antigo troca um engasgo por atraso permanente, e numa
// conversa ao vivo essa é a troca certa.
const bridgeMaxQueuedFrames = 5

// liveAudioBridge liga a sessão do atendente à chamada.
type liveAudioBridge struct {
	mu sync.Mutex

	// pending guarda amostras do microfone ainda não entregues, já em 16 kHz mono.
	pending []float32
	closed  bool

	// muted silencia o microfone do atendente (FR-026, FR-027).
	//
	// **A garantia é aqui, no servidor**, e não no `track.enabled = false` do navegador.
	// Aquele é espelho e economia de banda; este é o que cumpre FR-027, porque o navegador
	// roda em território não confiável.
	//
	// Divergência declarada da research §R5, encontrada na implementação: a pesquisa previa
	// `Player.Pause()`, que faz o motor substituir por silêncio. Funciona para o instante,
	// mas o microfone do navegador continua aberto e a fila desta ponte continua enchendo —
	// e ao reativar o contato receberia até 300 ms da conversa particular que o atendente
	// silenciou para ter. Descartar na entrada fecha isso: o que é capturado durante o
	// silenciamento não existe em lugar nenhum.
	muted bool

	// peerSink recebe a voz do contato. Trocável a quente: é isso que permite reconectar
	// sem derrubar a chamada, e é onde o tee da gravação se encaixa (research §R6).
	peerSink func([]float32)

	// droppedNoSink conta os quadros descartados por falta de destino. Existe para o log
	// sair uma vez por ponte, e não por quadro.
	droppedNoSink int

	// silence é devolvido no esvaziamento. Um único buffer compartilhado porque ninguém o
	// escreve — o laço de mídia só o lê para codificar.
	silence []float32
}

func newLiveAudioBridge() *liveAudioBridge {
	return &liveAudioBridge{
		pending: make([]float32, 0, bridgeMaxQueuedFrames*meowcaller.FrameSamples),
		silence: make([]float32, meowcaller.FrameSamples),
	}
}

// ReadFrame entrega o próximo quadro ao laço de mídia do meowcaller.
//
// **Nunca bloqueia**, e essa é a propriedade que mais importa neste arquivo. O laço chama
// isto a cada 60 ms; segurá-lo atrasa o fluxo para o contato e, pior, atrasa também o quadro
// seguinte — o atraso não se recupera, ele acumula.
//
// Quadro incompleto vira silêncio em vez de meio quadro: entregar amostras faltando produz
// um artefato audível, e é pior do que um instante de silêncio.
func (b *liveAudioBridge) ReadFrame() ([]float32, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, io.EOF
	}
	if len(b.pending) < meowcaller.FrameSamples {
		return b.silence, nil
	}

	frame := make([]float32, meowcaller.FrameSamples)
	copy(frame, b.pending[:meowcaller.FrameSamples])
	b.pending = b.pending[meowcaller.FrameSamples:]
	return frame, nil
}

// PushMic acrescenta amostras do microfone do atendente, já decodificadas.
//
// Chamado pela sessão WebRTC a cada pacote recebido — 20 ms de cada vez, no caso do Chrome.
// O agrupamento até o quadro de 60 ms acontece aqui, e não no decodificador, porque é aqui
// que existe a fila.
func (b *liveAudioBridge) PushMic(samples []float32) {
	if len(samples) == 0 {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.muted {
		// Silenciado: descarta na entrada. Enfileirar "para não perder áudio" transformaria
		// a pausa numa gravação com atraso.
		return
	}

	b.pending = append(b.pending, samples...)

	// Descarta o excedente pelo começo, mantendo o alinhamento de quadro: cortar em um
	// múltiplo de FrameSamples evita deslocar a fase do áudio, que produziria um estalo.
	max := bridgeMaxQueuedFrames * meowcaller.FrameSamples
	if len(b.pending) > max {
		excess := len(b.pending) - max
		excess += (meowcaller.FrameSamples - excess%meowcaller.FrameSamples) % meowcaller.FrameSamples
		if excess > len(b.pending) {
			excess = len(b.pending)
		}
		b.pending = b.pending[excess:]
	}
}

// WriteFrame recebe um quadro da voz do contato e o encaminha ao destino corrente.
//
// Nunca falha por falta de destino: durante o período de graça a sessão não tem para onde
// mandar o áudio, e a chamada precisa continuar viva assim mesmo (FR-037).
func (b *liveAudioBridge) WriteFrame(frame []float32) error {
	b.mu.Lock()
	sink := b.peerSink
	dropped := b.droppedNoSink
	if sink == nil {
		b.droppedNoSink++
	}
	b.mu.Unlock()

	if sink == nil {
		// Um dos dois pontos cegos do caminho de volta: sem destino, a voz do contato é
		// descartada sem deixar rastro, e "não tem áudio" fica indistinguível de "o contato
		// está calado". Registra só a primeira, para não inundar o log a 16 quadros por
		// segundo — a existência da linha é o diagnóstico, não a contagem.
		if dropped == 0 {
			log.Warn().
				Str("bridge", fmt.Sprintf("%p", b)).
				Msg("Softphone bridge has no peer sink; the contact's audio is being discarded")
		}
		return nil
	}
	sink(frame)
	return nil
}

// SetMuted silencia ou reativa o microfone do atendente.
//
// Silenciar descarta o que estiver pendente: são amostras de antes do clique, e entregá-las
// depois seria enviar justamente o que o atendente quis calar.
func (b *liveAudioBridge) SetMuted(muted bool) {
	b.mu.Lock()
	b.muted = muted
	if muted {
		b.pending = b.pending[:0]
	}
	b.mu.Unlock()
}

// Muted diz se o microfone está silenciado.
func (b *liveAudioBridge) Muted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.muted
}

// SetPeerSink aponta a voz do contato para um destino. Nil a descarta.
func (b *liveAudioBridge) SetPeerSink(sink func([]float32)) {
	if sink == nil {
		// Desarmar é legítimo — conexão caindo, sessão morrendo —, mas o log mostrou um
		// desarme que nenhum caminho conhecido explica. O rastro nomeia o responsável em
		// vez de deixar a dedução por conta de quem lê. Só no caso nulo: armar é rotina.
		log.Warn().
			Str("bridge", fmt.Sprintf("%p", b)).
			Str("stack", string(debug.Stack())).
			Msg("Softphone bridge peer sink cleared")
	}
	b.mu.Lock()
	b.peerSink = sink
	b.mu.Unlock()
}

// Reset descarta o áudio acumulado sem fechar a ponte.
//
// Usado ao reconectar: o que estava na fila é de antes da queda, e reproduzi-lo entregaria
// ao contato uma fala de vários segundos atrás.
//
// **Não** mexe no silenciamento: numa reconexão o atendente continua na mesma conversa, e
// reativar o microfone dele sozinho colocaria no ar o que ele calou de propósito. Quem zera
// o mudo é a anexação a uma chamada nova (FR-028).
func (b *liveAudioBridge) Reset() {
	b.mu.Lock()
	b.pending = b.pending[:0]
	b.mu.Unlock()
}

// Close encerra a ponte. Seguro chamar mais de uma vez, como o contrato de AudioSource exige.
func (b *liveAudioBridge) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.pending = nil
	b.peerSink = nil
	return nil
}

// A ponte satisfaz os dois lados do contrato de áudio do meowcaller.
var (
	_ meowcaller.AudioSource = (*liveAudioBridge)(nil)
	_ meowcaller.AudioSink   = (*liveAudioBridge)(nil)
)
