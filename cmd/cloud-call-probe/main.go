// Programa de prova de mídia entre o wuzapi e a Calling API da Meta (feature 028, T100).
//
// Atende uma ligação recebida ou faz uma ligação numa conta real, com uma PeerConnection do
// pion nas condições que o motor de ligações vai usar: ICE-full do nosso lado (a Meta é
// ICE-lite), cliente DTLS, Opus a 48 kHz, sem STUN. O áudio recebido volta como eco: quem fala
// no telefone se ouve, o que prova os dois sentidos. Antes do primeiro pacote da Meta, o
// programa envia silêncio, porque o lado da empresa envia o primeiro pacote.
//
// Credenciais só por variável de ambiente: META_ACCESS_TOKEN e META_PHONE_NUMBER_ID. O token
// nunca é impresso. Veja README.md nesta pasta.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/oggwriter"
)

// Quadro Opus de silêncio (CELT, 20 ms).
var opusSilence = []byte{0xF8, 0xFF, 0xFE}

const frameDuration = 20 * time.Millisecond

type config struct {
	mode        string
	to          string
	callID      string
	sdpFile     string
	listen      string
	seconds     int
	record      string
	graphVer    string
	verbose     bool
	token       string
	phoneNumber string
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.mode, "mode", "incoming", "incoming (atender) ou outgoing (ligar)")
	flag.StringVar(&cfg.to, "to", "", "outgoing: número do contato, só dígitos")
	flag.StringVar(&cfg.callID, "call-id", "", "incoming: callId da ligação (opcional quando o evento colado ou recebido o traz)")
	flag.StringVar(&cfg.sdpFile, "sdp-file", "-", "arquivo com a oferta (incoming) ou a resposta (outgoing): SDP puro ou o JSON do evento; '-' lê da entrada padrão")
	flag.StringVar(&cfg.listen, "listen", "", "endereço HTTP para receber o evento calls.update (ex.: :8088) em vez de -sdp-file")
	flag.IntVar(&cfg.seconds, "seconds", 60, "duração da ligação depois de estabelecida, em segundos")
	flag.StringVar(&cfg.record, "record", "", "arquivo .ogg para gravar o áudio recebido da Meta")
	flag.StringVar(&cfg.graphVer, "graph-version", envOr("GRAPH_API_VERSION", "v23.0"), "versão da Graph API")
	flag.BoolVar(&cfg.verbose, "v", false, "imprime os SDPs")
	flag.Parse()

	cfg.token = os.Getenv("META_ACCESS_TOKEN")
	cfg.phoneNumber = os.Getenv("META_PHONE_NUMBER_ID")
	if cfg.token == "" || cfg.phoneNumber == "" {
		fail("defina META_ACCESS_TOKEN e META_PHONE_NUMBER_ID")
	}
	if cfg.mode == "outgoing" && cfg.to == "" {
		fail("-to é obrigatório em -mode outgoing")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cfg.mode {
	case "incoming":
		err = runIncoming(ctx, cfg)
	case "outgoing":
		err = runOutgoing(ctx, cfg)
	default:
		err = fmt.Errorf("-mode inválido: %q", cfg.mode)
	}
	if err != nil {
		fail(err.Error())
	}
}

// ---------- fluxos ----------

func runIncoming(ctx context.Context, cfg config) error {
	fmt.Println("Aguardando a oferta da ligação recebida...")
	offer, callID, err := waitSessionSDP(ctx, cfg, "offer")
	if err != nil {
		return err
	}
	if cfg.callID != "" {
		callID = cfg.callID
	}
	if callID == "" {
		return errors.New("callId ausente: informe -call-id")
	}
	fmt.Printf("Oferta recebida para %s\n", callID)

	probe, err := newProbe(cfg)
	if err != nil {
		return err
	}
	defer probe.close()

	if err := probe.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		return fmt.Errorf("oferta recusada pelo pion: %w", err)
	}
	answer, err := probe.pc.CreateAnswer(nil)
	if err != nil {
		return err
	}
	local, err := probe.gather(answer)
	if err != nil {
		return err
	}
	checkLocalSDP(local, cfg.verbose)

	if err := graphCall(cfg, map[string]any{"call_id": callID, "action": "pre_accept", "session": map[string]string{"sdp_type": "answer", "sdp": local}}); err != nil {
		return fmt.Errorf("pre_accept: %w", err)
	}
	fmt.Println("pre_accept aceito pela Meta")
	probe.startMedia()
	if err := graphCall(cfg, map[string]any{"call_id": callID, "action": "accept", "session": map[string]string{"sdp_type": "answer", "sdp": local}}); err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	fmt.Println("accept aceito pela Meta. Fale no telefone: você deve se ouvir.")

	probe.run(ctx, cfg)
	terminate(cfg, callID)
	return probe.verdict()
}

func runOutgoing(ctx context.Context, cfg config) error {
	probe, err := newProbe(cfg)
	if err != nil {
		return err
	}
	defer probe.close()

	offer, err := probe.pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	local, err := probe.gather(offer)
	if err != nil {
		return err
	}
	checkLocalSDP(local, cfg.verbose)

	callID, err := graphConnect(cfg, local)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	fmt.Printf("connect aceito pela Meta: %s. Aguardando a resposta SDP do evento connect...\n", callID)

	answer, _, err := waitSessionSDP(ctx, cfg, "answer")
	if err != nil {
		terminate(cfg, callID)
		return err
	}
	if err := probe.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		terminate(cfg, callID)
		return fmt.Errorf("resposta recusada pelo pion: %w", err)
	}
	probe.startMedia()
	fmt.Println("Resposta aplicada. Atenda no telefone e fale: você deve se ouvir.")

	probe.run(ctx, cfg)
	terminate(cfg, callID)
	return probe.verdict()
}

// ---------- mídia ----------

type probe struct {
	pc       *webrtc.PeerConnection
	track    *webrtc.TrackLocalStaticSample
	ogg      *oggwriter.OggWriter
	echo     chan []byte
	sent     atomic.Int64
	received atomic.Int64
	first    atomic.Int64 // instante (unix ms) do primeiro pacote recebido
	started  atomic.Bool
	state    atomic.Value
}

func newProbe(cfg config) (*probe, error) {
	engine := &webrtc.MediaEngine{}
	if err := engine.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1"},
		PayloadType:        111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, err
	}
	settings := webrtc.SettingEngine{}
	// O lado da empresa é o cliente DTLS (a=setup:active).
	if err := settings.SetAnsweringDTLSRole(webrtc.DTLSRoleClient); err != nil {
		return nil, err
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(engine), webrtc.WithSettingEngine(settings))

	// Sem STUN nem TURN: a Meta é ICE-lite com IP público, e o nosso lado inicia os checks.
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return nil, err
	}
	track, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "audio", "cloud-call-probe")
	if err != nil {
		return nil, err
	}
	sender, err := pc.AddTrack(track)
	if err != nil {
		return nil, err
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := sender.Read(buf); err != nil {
				return
			}
		}
	}()

	p := &probe{pc: pc, track: track, echo: make(chan []byte, 50)}
	p.state.Store("new")
	if cfg.record != "" {
		if p.ogg, err = oggwriter.New(cfg.record, 48000, 2); err != nil {
			return nil, err
		}
	}

	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) { fmt.Printf("[ice] %s\n", s) })
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		p.state.Store(s.String())
		fmt.Printf("[conexão] %s\n", s)
	})
	pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		fmt.Printf("[faixa] %s recebida\n", remote.Codec().MimeType)
		for {
			pkt, _, err := remote.ReadRTP()
			if err != nil {
				return
			}
			p.onPacket(pkt)
		}
	})
	return p, nil
}

func (p *probe) onPacket(pkt *rtp.Packet) {
	if p.received.Add(1) == 1 {
		p.first.Store(time.Now().UnixMilli())
		fmt.Println("[mídia] primeiro pacote da Meta")
	}
	if p.ogg != nil {
		_ = p.ogg.WriteRTP(pkt)
	}
	payload := append([]byte(nil), pkt.Payload...)
	select {
	case p.echo <- payload:
	default: // eco atrasado: descarta em vez de acumular latência
	}
}

// gather aplica a descrição local e espera a coleta terminar: a Meta não aceita candidatos
// depois do SDP.
func (p *probe) gather(desc webrtc.SessionDescription) (string, error) {
	done := webrtc.GatheringCompletePromise(p.pc)
	if err := p.pc.SetLocalDescription(desc); err != nil {
		return "", err
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		fmt.Println("[aviso] coleta de candidatos não terminou em 10 s; seguindo com o que há")
	}
	return p.pc.LocalDescription().SDP, nil
}

// startMedia envia silêncio a cada 20 ms até o primeiro pacote da Meta, e depois o eco.
func (p *probe) startMedia() {
	if p.started.Swap(true) {
		return
	}
	go func() {
		ticker := time.NewTicker(frameDuration)
		defer ticker.Stop()
		for range ticker.C {
			data := opusSilence
			select {
			case payload := <-p.echo:
				data = payload
			default:
			}
			if err := p.track.WriteSample(media.Sample{Data: data, Duration: frameDuration}); err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					return
				}
				continue
			}
			p.sent.Add(1)
		}
	}()
}

func (p *probe) run(ctx context.Context, cfg config) {
	deadline := time.After(time.Duration(cfg.seconds) * time.Second)
	report := time.NewTicker(5 * time.Second)
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			return
		case <-report.C:
			fmt.Printf("[estado] conexão=%v enviados=%d recebidos=%d\n", p.state.Load(), p.sent.Load(), p.received.Load())
			if s, _ := p.state.Load().(string); s == "failed" || s == "closed" {
				return
			}
		}
	}
}

func (p *probe) verdict() error {
	sent, received := p.sent.Load(), p.received.Load()
	fmt.Println("\n===== Resultado =====")
	fmt.Printf("Pacotes enviados à Meta:   %d\n", sent)
	fmt.Printf("Pacotes recebidos da Meta: %d\n", received)
	if received == 0 {
		fmt.Println("Entrada: FALHOU (nenhum pacote da Meta)")
		return errors.New("sem áudio da Meta")
	}
	fmt.Println("Entrada: OK")
	fmt.Println("Saída: confirme pelo ouvido. Você se ouviu no telefone? A Meta derruba a ligação depois de 20 a 30 s sem mídia; se a ligação durou o tempo todo, a Meta recebeu os pacotes.")
	return nil
}

func (p *probe) close() {
	if p.ogg != nil {
		_ = p.ogg.Close()
	}
	_ = p.pc.Close()
}

func checkLocalSDP(sdp string, verbose bool) {
	if verbose {
		fmt.Println("----- SDP local -----")
		fmt.Println(sdp)
	}
	checks := map[string]bool{
		"a=setup:active":          strings.Contains(sdp, "a=setup:active") || strings.Contains(sdp, "a=setup:actpass"),
		"uma seção m=audio":       strings.Count(sdp, "m=audio ") == 1,
		"opus/48000":              strings.Contains(strings.ToLower(sdp), "opus/48000"),
		"a=fingerprint":           strings.Contains(sdp, "a=fingerprint:"),
		"a=ice-ufrag e a=ice-pwd": strings.Contains(sdp, "a=ice-ufrag:") && strings.Contains(sdp, "a=ice-pwd:"),
		"candidatos no SDP":       strings.Contains(sdp, "a=candidate:"),
	}
	for name, ok := range checks {
		mark := "ok"
		if !ok {
			mark = "FALTA"
		}
		fmt.Printf("[sdp] %-24s %s\n", name, mark)
	}
}

// ---------- SDP de entrada ----------

// waitSessionSDP obtém o SDP do evento: pelo endpoint HTTP (-listen) ou do arquivo/entrada.
func waitSessionSDP(ctx context.Context, cfg config, wantType string) (string, string, error) {
	if cfg.listen != "" {
		return listenForSDP(ctx, cfg.listen, wantType)
	}
	var reader io.Reader = os.Stdin
	if cfg.sdpFile != "-" {
		f, err := os.Open(cfg.sdpFile)
		if err != nil {
			return "", "", err
		}
		defer f.Close()
		reader = f
	} else {
		fmt.Println("Cole o SDP ou o JSON do evento e termine com uma linha vazia:")
	}
	raw, err := readUntilBlank(reader)
	if err != nil {
		return "", "", err
	}
	return extractSDP(raw, wantType)
}

func readUntilBlank(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" && buf.Len() > 0 {
			break
		}
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	return buf.Bytes(), scanner.Err()
}

// extractSDP aceita SDP puro, o envelope calls.update da ZapperHub (session.sdp) ou o corpo da
// Meta (entry[0].changes[0].value.calls[0].session.sdp). Normaliza as quebras para CRLF.
func extractSDP(raw []byte, wantType string) (string, string, error) {
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, "v=0") {
		return normalizeSDP(text), "", nil
	}
	var event struct {
		CallID  string `json:"callId"`
		Session *struct {
			SDPType string `json:"sdpType"`
			SDP     string `json:"sdp"`
		} `json:"session"`
		Entry []struct {
			Changes []struct {
				Value struct {
					Calls []struct {
						ID      string `json:"id"`
						Session *struct {
							SDPType string `json:"sdp_type"`
							SDP     string `json:"sdp"`
						} `json:"session"`
					} `json:"calls"`
				} `json:"value"`
			} `json:"changes"`
		} `json:"entry"`
	}
	if err := json.Unmarshal([]byte(text), &event); err != nil {
		return "", "", fmt.Errorf("entrada não é SDP nem JSON: %w", err)
	}
	if event.Session != nil && event.Session.SDP != "" {
		if event.Session.SDPType != "" && event.Session.SDPType != wantType {
			return "", "", fmt.Errorf("o evento traz %q, esperado %q", event.Session.SDPType, wantType)
		}
		return normalizeSDP(event.Session.SDP), event.CallID, nil
	}
	for _, entry := range event.Entry {
		for _, change := range entry.Changes {
			for _, call := range change.Value.Calls {
				if call.Session != nil && call.Session.SDP != "" {
					if call.Session.SDPType != "" && call.Session.SDPType != wantType {
						return "", "", fmt.Errorf("o evento traz %q, esperado %q", call.Session.SDPType, wantType)
					}
					return normalizeSDP(call.Session.SDP), call.ID, nil
				}
			}
		}
	}
	return "", "", errors.New("nenhum session.sdp no JSON")
}

func normalizeSDP(sdp string) string {
	sdp = strings.ReplaceAll(sdp, "\r\n", "\n")
	return strings.ReplaceAll(strings.TrimRight(sdp, "\n"), "\n", "\r\n") + "\r\n"
}

// listenForSDP recebe POSTs com o evento e devolve o primeiro que traz SDP do tipo esperado.
func listenForSDP(ctx context.Context, addr, wantType string) (string, string, error) {
	type result struct{ sdp, callID string }
	found := make(chan result, 1)
	server := &http.Server{Addr: addr, ReadHeaderTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verificação do webhook pela Meta: devolve o desafio. O corpo do pedido nunca é impresso.
		if challenge := r.URL.Query().Get("hub.challenge"); r.Method == http.MethodGet && challenge != "" {
			fmt.Printf("[http] GET %s: verificação do webhook respondida\n", r.URL.Path)
			_, _ = io.WriteString(w, challenge)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		w.WriteHeader(http.StatusOK)
		sdp, callID, err := extractSDP(body, wantType)
		if err != nil {
			fmt.Printf("[http] %s %s (%d bytes) ignorado: %v\n", r.Method, r.URL.Path, len(body), err)
			return
		}
		fmt.Printf("[http] %s %s (%d bytes): evento com SDP\n", r.Method, r.URL.Path, len(body))
		select {
		case found <- result{sdp, callID}:
		default:
		}
	})
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return "", "", fmt.Errorf("não foi possível escutar em %s: %w", addr, err)
	}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	fmt.Printf("Escutando eventos em %s\n", addr)
	select {
	case res := <-found:
		return res.sdp, res.callID, nil
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
}

// ---------- Graph API ----------

func graphCall(cfg config, body map[string]any) error {
	_, err := graphPost(cfg, body)
	return err
}

func graphConnect(cfg config, offer string) (string, error) {
	data, err := graphPost(cfg, map[string]any{"to": cfg.to, "action": "connect", "session": map[string]string{"sdp_type": "offer", "sdp": offer}})
	if err != nil {
		return "", err
	}
	var resp struct {
		Calls []struct {
			ID string `json:"id"`
		} `json:"calls"`
	}
	if err := json.Unmarshal(data, &resp); err != nil || len(resp.Calls) == 0 {
		return "", fmt.Errorf("resposta sem callId: %s", data)
	}
	return resp.Calls[0].ID, nil
}

func terminate(cfg config, callID string) {
	if err := graphCall(cfg, map[string]any{"call_id": callID, "action": "terminate"}); err != nil {
		fmt.Printf("[aviso] terminate: %v\n", err)
		return
	}
	fmt.Println("terminate aceito pela Meta")
}

// graphPost manda o comando uma vez só, sem retentativa, como o manager.
func graphPost(cfg config, body map[string]any) ([]byte, error) {
	body["messaging_product"] = "whatsapp"
	payload, _ := json.Marshal(body)
	url := fmt.Sprintf("https://graph.facebook.com/%s/%s/calls", cfg.graphVer, cfg.phoneNumber)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, data)
	}
	return data, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "erro:", msg)
	os.Exit(1)
}
