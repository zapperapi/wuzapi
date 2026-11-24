package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/polymorfa/hypermeow/proto/waMmsRetry"
	"github.com/polymorfa/hypermeow/types"
	"github.com/polymorfa/hypermeow/types/events"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"
)

// receivedMedia é a mídia baixável de uma mensagem recebida.
type receivedMedia struct {
	// field é o campo da mídia no protobuf (imageMessage, ptvMessage...).
	field    string
	msg      whatsmeow.DownloadableMessage
	mimeType string
	ext      string
	timeout  time.Duration
	extra    map[string]interface{}
}

// receivedMediaOf devolve a mídia da mensagem, já desembrulhada pelo
// UnwrapRaw. Uma mensagem tem no máximo uma mídia.
//
// PTV (vídeo redondo) e os tipos instant são VideoMessage e ImageMessage em
// outro campo do protobuf; o WhatsApp Web os baixa como vídeo e imagem
// (WAWebMmsMediaTypes, função c).
func receivedMediaOf(m *waE2E.Message) (receivedMedia, bool) {
	if m == nil {
		return receivedMedia{}, false
	}
	if img := m.GetImageMessage(); img != nil {
		return receivedMedia{"imageMessage", img, img.GetMimetype(), ".jpg", downloadTimeoutImage, nil}, true
	}
	if img := m.GetInstantImageMessage(); img != nil {
		return receivedMedia{"instantImageMessage", img, img.GetMimetype(), ".jpg", downloadTimeoutImage, nil}, true
	}
	if audio := m.GetAudioMessage(); audio != nil {
		return receivedMedia{"audioMessage", audio, audio.GetMimetype(), ".ogg", downloadTimeoutAudio, nil}, true
	}
	if doc := m.GetDocumentMessage(); doc != nil {
		ext := ".bin"
		if doc.FileName != nil {
			ext = filepath.Ext(*doc.FileName)
		}
		return receivedMedia{"documentMessage", doc, doc.GetMimetype(), ext, downloadTimeoutDocument, nil}, true
	}
	if video := m.GetVideoMessage(); video != nil {
		return receivedMedia{"videoMessage", video, video.GetMimetype(), ".mp4", downloadTimeoutVideo, nil}, true
	}
	if ptv := m.GetPtvMessage(); ptv != nil {
		return receivedMedia{"ptvMessage", ptv, ptv.GetMimetype(), ".mp4", downloadTimeoutVideo, nil}, true
	}
	if video := m.GetInstantVideoMessage(); video != nil {
		return receivedMedia{"instantVideoMessage", video, video.GetMimetype(), ".mp4", downloadTimeoutVideo, nil}, true
	}
	if sticker := m.GetStickerMessage(); sticker != nil {
		return receivedMedia{"stickerMessage", sticker, sticker.GetMimetype(), ".webp", downloadTimeoutSticker, map[string]interface{}{
			"isSticker":       true,
			"stickerAnimated": sticker.GetIsAnimated(),
		}}, true
	}
	return receivedMedia{}, false
}

// messageAssociationOf resume o vínculo da mensagem com uma mensagem pai
// (versão HD, original, vídeo de motion photo, item de álbum). O tipo sai com
// o nome do enum, para não depender do número.
func messageAssociationOf(m *waE2E.Message) map[string]interface{} {
	association := m.GetMessageContextInfo().GetMessageAssociation()
	if association == nil {
		return nil
	}
	out := map[string]interface{}{
		"type": association.GetAssociationType().String(),
	}
	if parent := association.GetParentMessageKey(); parent.GetID() != "" {
		out["parentId"] = parent.GetID()
		out["parentFromMe"] = parent.GetFromMe()
		if jid := parent.GetRemoteJID(); jid != "" {
			out["parentRemoteJid"] = jid
		}
		if participant := parent.GetParticipant(); participant != "" {
			out["parentParticipant"] = participant
		}
	}
	return out
}

// isExpiredMediaError diz se o download falhou porque o arquivo saiu do
// servidor de mídia. Só nesses casos o aparelho que enviou pode reenviar.
func isExpiredMediaError(err error) bool {
	return errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith404) ||
		errors.Is(err, whatsmeow.ErrMediaDownloadFailedWith410)
}

// setDirectPath troca o caminho da mídia pelo que veio na notificação de
// reupload.
func setDirectPath(msg whatsmeow.DownloadableMessage, path string) bool {
	switch m := msg.(type) {
	case *waE2E.ImageMessage:
		m.DirectPath = proto.String(path)
	case *waE2E.VideoMessage:
		m.DirectPath = proto.String(path)
	case *waE2E.AudioMessage:
		m.DirectPath = proto.String(path)
	case *waE2E.DocumentMessage:
		m.DirectPath = proto.String(path)
	case *waE2E.StickerMessage:
		m.DirectPath = proto.String(path)
	default:
		return false
	}
	return true
}

// mediaRetryTTL é quanto tempo um pedido de reupload espera a resposta. O
// aparelho que enviou responde quando fica online, o que pode levar horas.
const mediaRetryTTL = 24 * time.Hour

// pendingMediaRetry é um pedido de reupload sem resposta. Guarda a mídia
// (com a mediaKey, que decifra a notificação) e o que o download precisa.
type pendingMediaRetry struct {
	info       types.MessageInfo
	media      receivedMedia
	chatJID    string
	isIncoming bool
	s3cfg      mediaS3Config
	// association é o vínculo da mensagem com a pai (versão HD, por exemplo),
	// para a mídia que chegar depois ir para a mensagem certa.
	association map[string]interface{}
	expires     time.Time
}

// mediaRetryStore guarda os pedidos de reupload em memória. Um pedido feito
// antes de reiniciar o processo se perde, e a mídia continua sem chegar.
type mediaRetryStore struct {
	mu      sync.Mutex
	pending map[string]*pendingMediaRetry
}

var mediaRetries = &mediaRetryStore{pending: make(map[string]*pendingMediaRetry)}

func mediaRetryKey(userID string, messageID types.MessageID) string {
	return userID + "/" + string(messageID)
}

// add guarda o pedido e devolve false se já havia um para a mesma mensagem.
func (s *mediaRetryStore) add(userID string, entry *pendingMediaRetry, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, p := range s.pending {
		if now.After(p.expires) {
			delete(s.pending, key)
		}
	}
	key := mediaRetryKey(userID, entry.info.ID)
	if _, exists := s.pending[key]; exists {
		return false
	}
	entry.expires = now.Add(mediaRetryTTL)
	s.pending[key] = entry
	return true
}

// take tira o pedido da lista. A notificação de reupload só vale uma vez.
func (s *mediaRetryStore) take(userID string, messageID types.MessageID, now time.Time) (*pendingMediaRetry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := mediaRetryKey(userID, messageID)
	p, ok := s.pending[key]
	if !ok {
		return nil, false
	}
	delete(s.pending, key)
	if now.After(p.expires) {
		return nil, false
	}
	return p, true
}

// requestMediaReupload pede ao aparelho que enviou a mensagem que suba a mídia
// de novo, como o WhatsApp Web faz quando o download dá 404 ou 410
// (WAWebRequestMediaReuploadManager). A resposta chega como events.MediaRetry.
// Canal não aceita o pedido (RMRNotSupportedOnNewsletterMessagesError).
func (mycli *MyClient) requestMediaReupload(info *types.MessageInfo, media receivedMedia, association map[string]interface{}, chatJID string, isIncoming bool, s3cfg mediaS3Config) bool {
	if info.Chat.Server == types.NewsletterServer {
		return false
	}
	mediaKey := media.msg.GetMediaKey()
	if len(mediaKey) == 0 {
		return false
	}
	entry := &pendingMediaRetry{
		info:        *info,
		media:       media,
		chatJID:     chatJID,
		isIncoming:  isIncoming,
		s3cfg:       s3cfg,
		association: association,
	}
	if !mediaRetries.add(mycli.userID, entry, time.Now()) {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mycli.WAClient.SendMediaRetryReceipt(ctx, info, mediaKey); err != nil {
		mediaRetries.take(mycli.userID, info.ID, time.Now())
		log.Warn().Err(err).Str("messageID", info.ID).Msg("Failed to request media reupload")
		return false
	}
	log.Info().Str("messageID", info.ID).Msg("Media expired on the server; reupload requested")
	return true
}

// mediaRetryResult é o resultado público do reupload: "success" ou o motivo
// da falha.
func mediaRetryResult(notif *waMmsRetry.MediaRetryNotification, err error) string {
	switch {
	case errors.Is(err, whatsmeow.ErrMediaNotAvailableOnPhone):
		return "not_on_phone"
	case err != nil:
		return "decryption_error"
	case notif.GetResult() == waMmsRetry.MediaRetryNotification_SUCCESS && notif.GetDirectPath() != "":
		return "success"
	case notif.GetResult() == waMmsRetry.MediaRetryNotification_SUCCESS:
		return "general_error"
	default:
		return strings.ToLower(notif.GetResult().String())
	}
}

// handleMediaRetry trata a resposta do aparelho a um pedido de reupload. Com
// sucesso, baixa a mídia pelo caminho novo e manda o webhook `MediaRetry` com
// o mesmo `s3`/`base64` de um `Message`. Sem pedido pendente (o processo
// reiniciou, ou o pedido não saiu daqui), não há mediaKey para decifrar e o
// evento é descartado.
func (mycli *MyClient) handleMediaRetry(evt *events.MediaRetry) {
	pending, ok := mediaRetries.take(mycli.userID, evt.MessageID, time.Now())
	if !ok {
		log.Debug().Str("messageID", evt.MessageID).Msg("Media retry without a pending request")
		return
	}

	notif, err := whatsmeow.DecryptMediaRetryNotification(evt, pending.media.msg.GetMediaKey())
	result := mediaRetryResult(notif, err)

	postmap := map[string]interface{}{
		"type": "MediaRetry",
		"event": map[string]interface{}{
			"MessageID": evt.MessageID,
			"Chat":      pending.info.Chat.String(),
			"Sender":    pending.info.Sender.String(),
			"IsFromMe":  pending.info.IsFromMe,
			"IsGroup":   pending.info.IsGroup,
			"Timestamp": evt.Timestamp,
			"MediaType": pending.media.field,
			"Mimetype":  pending.media.mimeType,
		},
	}
	if pending.association != nil {
		postmap["association"] = pending.association
	}

	if result == "success" && setDirectPath(pending.media.msg, notif.GetDirectPath()) {
		if derr := mycli.processMedia(pending.media, pending.isIncoming, pending.chatJID, evt.MessageID, pending.s3cfg, postmap); derr != nil {
			result = "download_failed"
		}
	} else if result == "success" {
		result = "general_error"
	}
	postmap["result"] = result

	log.Info().Str("messageID", evt.MessageID).Str("result", result).Msg("Media retry answered")
	sendEventWithWebHook(mycli, postmap, "")
}
