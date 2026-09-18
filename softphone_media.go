package main

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/rs/zerolog/log"

	"wuzapi/internal/meowcaller"
)

// Sessão de mídia com o navegador do atendente (feature 021, research §R2).
//
// WebRTC, e não áudio dentro do próprio WebSocket. O que o WebRTC entrega e que teríamos de
// escrever à mão em qualquer outro transporte: buffer de jitter adaptativo, ocultação de
// perda de pacote e a referência de cancelamento de eco no navegador. É a parte que custou
// anos ao NetEq, e reimplementá-la em JavaScript dentro da biblioteca embutível seria trocar
// qualidade por controle que não queremos exercer.
//
// **Uma porta UDP, muxada.** Todas as sessões do processo compartilham a mesma porta
// (`SetICEUDPMux`), então não há faixa efêmera a liberar no firewall nem regra dinâmica. Uma
// porta TCP faz o mesmo papel para redes que bloqueiam UDP por completo — rota de fuga, não
// caminho padrão: ICE-TCP degrada sob perda pelas mesmas razões que qualquer áudio em TCP.

const (
	// mediaTrackID e mediaStreamID identificam a faixa que devolvemos ao navegador.
	mediaTrackID  = "softphone-audio"
	mediaStreamID = "softphone"

	// mediaOpusClockRate é o relógio RTP do Opus, fixo em 48 kHz pela especificação,
	// independentemente da taxa em que o áudio é de fato codificado.
	mediaOpusClockRate = 48000

	// mediaFrameDuration é a duração do quadro que enviamos ao navegador. Igual ao quadro
	// nativo do meowcaller, o que torna a descida 1:1 — sem refragmentação.
	mediaFrameDuration = time.Duration(meowcaller.FrameSamples) * time.Second / meowcaller.SampleRate

	// mediaGatherTimeout limita a coleta de candidatos ICE.
	//
	// A coleta é completa antes da resposta (sem trickle), o que simplifica o protocolo: a
	// sessão de mídia é estabelecida uma vez, na abertura, e vive enquanto a sessão viver.
	// Como isso acontece **antes** de qualquer chamada, o custo não entra no orçamento de
	// SC-003 nem no de SC-004 — ao contrário, deixa o caminho de voz aquecido para quando o
	// contato atender.
	mediaGatherTimeout = 5 * time.Second
)

var (
	// mediaEngineOnce protege a construção da API compartilhada: os multiplexadores de
	// porta são recursos do processo, e criar um por sessão tentaria vincular a mesma porta
	// várias vezes.
	mediaEngineOnce sync.Once
	mediaAPI        *webrtc.API
	mediaAPIErr     error
)

// softphoneMedia é a ponta WebRTC de uma sessão de atendente.
type softphoneMedia struct {
	pc    *webrtc.PeerConnection
	track *webrtc.TrackLocalStaticSample

	encoder *opusEncoder
	encMu   sync.Mutex

	bridge *liveAudioBridge

	closeOnce sync.Once
}

// softphoneMediaAPI monta a API do pion uma vez por processo.
func softphoneMediaAPI() (*webrtc.API, error) {
	mediaEngineOnce.Do(func() {
		engine := &webrtc.MediaEngine{}
		// Só Opus, e só áudio. Não registrar vídeo é o que garante que uma oferta com faixa
		// de vídeo simplesmente não negocia nada — em vez de negociar e ficar pendurada.
		if err := engine.RegisterCodec(webrtc.RTPCodecParameters{
			RTPCodecCapability: webrtc.RTPCodecCapability{
				MimeType:    webrtc.MimeTypeOpus,
				ClockRate:   mediaOpusClockRate,
				Channels:    2,
				SDPFmtpLine: "minptime=10;useinbandfec=1",
			},
			PayloadType: 111,
		}, webrtc.RTPCodecTypeAudio); err != nil {
			mediaAPIErr = err
			return
		}

		settings := webrtc.SettingEngine{}

		// Respeita PION_LOG_ICE=trace e afins, para que o próximo problema de mídia se
		// diagnostique por variável de ambiente em vez de captura de pacotes.
		settings.LoggerFactory = logging.NewDefaultLoggerFactory()

		// O mesmo filtro nos dois lugares, e isso não é redundância: o mux decide em que
		// endereços liga, o SettingEngine decide de quais endereços o agente coleta
		// candidatos. Divergirem é justamente o estado que deixa a sessão registrada numa
		// interface enquanto o navegador chega por outra — pacote entregue pelo kernel e
		// descartado pelo pion, sem resposta e sem log.
		settings.SetIPFilter(softphone.allowsMediaIP)

		udpMux, err := ice.NewMultiUDPMuxFromPort(
			softphone.mediaUDPPort,
			ice.UDPMuxFromPortWithIPFilter(softphone.allowsMediaIP),
		)
		if err != nil {
			mediaAPIErr = fmt.Errorf("softphone: udp mux on port %d: %w", softphone.mediaUDPPort, err)
			return
		}
		settings.SetICEUDPMux(udpMux)

		// Sem declarar os tipos TCP, o pion coleta apenas candidatos UDP e o `SetICETCPMux`
		// abaixo nunca chega a ser anunciado — a rota de fuga existiria no servidor e não
		// no SDP, que é onde ela precisa aparecer.
		settings.SetNetworkTypes([]webrtc.NetworkType{
			webrtc.NetworkTypeUDP4, webrtc.NetworkTypeUDP6,
			webrtc.NetworkTypeTCP4, webrtc.NetworkTypeTCP6,
		})

		// ICE-TCP na porta única. Falhar aqui não impede a mídia: só remove a rota de fuga.
		if listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: softphone.mediaTCPPort}); err == nil {
			settings.SetICETCPMux(webrtc.NewICETCPMux(nil, listener, 8))
		} else {
			log.Warn().Err(err).Int("port", softphone.mediaTCPPort).
				Msg("Softphone ICE-TCP unavailable; UDP-only networks will still work")
		}

		// Sem isto o navegador recebe o endereço interno do contêiner e nenhuma mídia se
		// estabelece — o modo de falha mais comum e mais confuso desta feature.
		if softphone.publicIP != "" {
			settings.SetNAT1To1IPs([]string{softphone.publicIP}, webrtc.ICECandidateTypeHost)
		}

		mediaAPI = webrtc.NewAPI(
			webrtc.WithMediaEngine(engine),
			webrtc.WithSettingEngine(settings),
		)
	})
	return mediaAPI, mediaAPIErr
}

// newSoftphoneMedia negocia a sessão de mídia a partir da oferta do navegador e devolve a
// resposta SDP já com os candidatos coletados.
func newSoftphoneMedia(offerSDP string, bridge *liveAudioBridge) (*softphoneMedia, string, error) {
	api, err := softphoneMediaAPI()
	if err != nil {
		return nil, "", err
	}

	// Sem servidores STUN: o lado público é o nosso, e o navegador atrás de NAT abre o
	// mapeamento de saída ao responder. Um STUN externo só acrescentaria latência de
	// negociação e uma dependência de terceiro no caminho de estabelecimento.
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, "", fmt.Errorf("softphone: peer connection: %w", err)
	}

	session := &softphoneMedia{pc: pc, bridge: bridge}

	encoder, err := newOpusEncoder()
	if err != nil {
		_ = pc.Close()
		return nil, "", err
	}
	session.encoder = encoder

	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: mediaOpusClockRate, Channels: 2},
		mediaTrackID, mediaStreamID,
	)
	if err != nil {
		session.Close()
		return nil, "", fmt.Errorf("softphone: local track: %w", err)
	}
	if _, err := pc.AddTrack(track); err != nil {
		session.Close()
		return nil, "", fmt.Errorf("softphone: add track: %w", err)
	}
	session.track = track

	pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		session.consumeMicrophone(remote)
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offerSDP,
	}); err != nil {
		session.Close()
		return nil, "", fmt.Errorf("softphone: remote description: %w", err)
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		session.Close()
		return nil, "", fmt.Errorf("softphone: create answer: %w", err)
	}

	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		session.Close()
		return nil, "", fmt.Errorf("softphone: local description: %w", err)
	}

	select {
	case <-gathered:
	case <-time.After(mediaGatherTimeout):
		// Coleta incompleta ainda costuma render uma resposta utilizável: os candidatos
		// host, que são os que importam quando o servidor tem IP público, chegam primeiro.
		log.Warn().Msg("Softphone ICE gathering timed out; answering with what was gathered")
	}

	local := pc.LocalDescription()
	if local == nil {
		session.Close()
		return nil, "", errors.New("softphone: no local description after gathering")
	}

	// Quem arma o caminho de volta na ponte é `agentSession.setMedia`, e não este
	// construtor. Armar aqui punha a mídia nova na ponte **antes** de a anterior ser
	// fechada, e o `Close` da anterior desarmava o que a nova tinha acabado de instalar.
	return session, local.SDP, nil
}

// consumeMicrophone decodifica os pacotes do navegador e os entrega à ponte.
//
// Um pacote corrompido é registrado e descartado, nunca encerra a leitura: rede real entrega
// lixo de vez em quando, e uma chamada que cai por causa de um pacote é uma chamada que cai.
func (m *softphoneMedia) consumeMicrophone(remote *webrtc.TrackRemote) {
	decoder, err := newOpusDecoder()
	if err != nil {
		log.Error().Err(err).Msg("Softphone could not create opus decoder")
		return
	}
	defer decoder.Close()

	for {
		packet, _, err := remote.ReadRTP()
		if err != nil {
			return
		}
		if len(packet.Payload) == 0 {
			continue
		}
		samples, err := decoder.Decode(packet.Payload)
		if err != nil {
			log.Debug().Err(err).Msg("Softphone dropped an undecodable audio packet")
			continue
		}
		m.bridge.PushMic(samples)
	}
}

// sendToBrowser codifica um quadro da voz do contato e o publica na faixa.
//
// O quadro do meowcaller tem exatamente 60 ms, que é um tamanho de quadro Opus válido — a
// descida é 1:1, sem refragmentação nem buffer intermediário.
func (m *softphoneMedia) sendToBrowser(frame []float32) {
	m.encMu.Lock()
	encoder := m.encoder
	var packet []byte
	var err error
	if encoder != nil {
		packet, err = encoder.Encode(frame)
	}
	m.encMu.Unlock()

	if encoder == nil {
		return
	}
	if err != nil {
		log.Debug().Err(err).Msg("Softphone could not encode a frame for the browser")
		return
	}
	if err := m.track.WriteSample(media.Sample{Data: packet, Duration: mediaFrameDuration}); err != nil {
		log.Debug().Err(err).Msg("Softphone could not deliver a frame to the browser")
	}
}

// ConnectionState devolve o estado corrente da conexão.
func (m *softphoneMedia) ConnectionState() webrtc.PeerConnectionState {
	return m.pc.ConnectionState()
}

// OnStateChange registra o observador de estado, de onde saem os gatilhos do período de
// graça (FR-037).
func (m *softphoneMedia) OnStateChange(fn func(webrtc.PeerConnectionState)) {
	m.pc.OnConnectionStateChange(fn)
}

// Close encerra a sessão de mídia. Seguro chamar mais de uma vez.
func (m *softphoneMedia) Close() {
	m.closeOnce.Do(func() {
		if m.bridge != nil {
			m.bridge.SetPeerSink(nil)
		}
		m.encMu.Lock()
		if m.encoder != nil {
			m.encoder.Close()
			m.encoder = nil
		}
		m.encMu.Unlock()
		if m.pc != nil {
			_ = m.pc.Close()
		}
	})
}
