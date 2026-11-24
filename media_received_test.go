package main

import (
	"fmt"
	"testing"
	"time"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/proto/waCommon"
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/polymorfa/hypermeow/proto/waMmsRetry"
	"github.com/polymorfa/hypermeow/types"
	"google.golang.org/protobuf/proto"
)

func TestReceivedMediaOf(t *testing.T) {
	video := &waE2E.VideoMessage{Mimetype: proto.String("video/mp4")}
	image := &waE2E.ImageMessage{Mimetype: proto.String("image/jpeg")}

	tests := map[string]struct {
		msg   *waE2E.Message
		field string
		want  whatsmeow.DownloadableMessage
	}{
		"ptv":           {&waE2E.Message{PtvMessage: video}, "ptvMessage", video},
		"instant video": {&waE2E.Message{InstantVideoMessage: video}, "instantVideoMessage", video},
		"instant image": {&waE2E.Message{InstantImageMessage: image}, "instantImageMessage", image},
		"video":         {&waE2E.Message{VideoMessage: video}, "videoMessage", video},
		"image":         {&waE2E.Message{ImageMessage: image}, "imageMessage", image},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			media, ok := receivedMediaOf(tc.msg)
			if !ok || media.field != tc.field || media.msg != tc.want {
				t.Fatalf("got field %q, msg %v, ok %t", media.field, media.msg, ok)
			}
		})
	}

	if _, ok := receivedMediaOf(&waE2E.Message{Conversation: proto.String("oi")}); ok {
		t.Error("text message has no media")
	}
	if media, ok := receivedMediaOf(&waE2E.Message{PtvMessage: video}); !ok || media.ext != ".mp4" || media.timeout != downloadTimeoutVideo {
		t.Errorf("ptv downloads as video: ext %q, timeout %v", media.ext, media.timeout)
	}
}

func TestMessageAssociationOf(t *testing.T) {
	msg := &waE2E.Message{
		ImageMessage: &waE2E.ImageMessage{},
		MessageContextInfo: &waE2E.MessageContextInfo{MessageAssociation: &waE2E.MessageAssociation{
			AssociationType: waE2E.MessageAssociation_HD_IMAGE_DUAL_UPLOAD.Enum(),
			ParentMessageKey: &waCommon.MessageKey{
				RemoteJID:   proto.String("120363000000000000@g.us"),
				FromMe:      proto.Bool(false),
				ID:          proto.String("3EB0PARENT"),
				Participant: proto.String("123456789@lid"),
			},
		}},
	}
	got := messageAssociationOf(msg)
	want := map[string]interface{}{
		"type":              "HD_IMAGE_DUAL_UPLOAD",
		"parentId":          "3EB0PARENT",
		"parentFromMe":      false,
		"parentRemoteJid":   "120363000000000000@g.us",
		"parentParticipant": "123456789@lid",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if got := messageAssociationOf(&waE2E.Message{ImageMessage: &waE2E.ImageMessage{}}); got != nil {
		t.Errorf("no association: got %v", got)
	}
}

func TestIsExpiredMediaError(t *testing.T) {
	if !isExpiredMediaError(fmt.Errorf("download: %w", whatsmeow.ErrMediaDownloadFailedWith404)) ||
		!isExpiredMediaError(whatsmeow.ErrMediaDownloadFailedWith410) {
		t.Error("404 and 410 mean the media left the server")
	}
	if isExpiredMediaError(whatsmeow.ErrMediaDownloadFailedWith403) || isExpiredMediaError(nil) {
		t.Error("403 and nil do not")
	}
}

func TestSetDirectPath(t *testing.T) {
	ptv := &waE2E.VideoMessage{DirectPath: proto.String("/v/old")}
	if !setDirectPath(ptv, "/v/new") || ptv.GetDirectPath() != "/v/new" {
		t.Errorf("direct path = %q", ptv.GetDirectPath())
	}
}

func TestMediaRetryStore(t *testing.T) {
	store := &mediaRetryStore{pending: make(map[string]*pendingMediaRetry)}
	now := time.Now()
	entry := func(id types.MessageID) *pendingMediaRetry {
		return &pendingMediaRetry{info: types.MessageInfo{ID: id}}
	}

	if !store.add("u1", entry("A"), now) {
		t.Fatal("first request is added")
	}
	if store.add("u1", entry("A"), now) {
		t.Error("second request for the same message is not")
	}
	if !store.add("u2", entry("A"), now) {
		t.Error("same message id on another instance is a different request")
	}

	if _, ok := store.take("u1", "A", now); !ok {
		t.Fatal("take finds the request")
	}
	if _, ok := store.take("u1", "A", now); ok {
		t.Error("a notification is used only once")
	}

	store.add("u1", entry("B"), now)
	if _, ok := store.take("u1", "B", now.Add(mediaRetryTTL+time.Minute)); ok {
		t.Error("expired request is not answered")
	}

	store.add("u1", entry("C"), now)
	store.add("u1", entry("D"), now.Add(mediaRetryTTL+time.Minute))
	if _, ok := store.pending[mediaRetryKey("u1", "C")]; ok {
		t.Error("add removes expired requests")
	}
}

func TestMediaRetryResult(t *testing.T) {
	notif := func(result waMmsRetry.MediaRetryNotification_ResultType, path string) *waMmsRetry.MediaRetryNotification {
		n := &waMmsRetry.MediaRetryNotification{Result: result.Enum()}
		if path != "" {
			n.DirectPath = proto.String(path)
		}
		return n
	}
	tests := map[string]struct {
		notif *waMmsRetry.MediaRetryNotification
		err   error
		want  string
	}{
		"success":          {notif(waMmsRetry.MediaRetryNotification_SUCCESS, "/v/new"), nil, "success"},
		"success, no path": {notif(waMmsRetry.MediaRetryNotification_SUCCESS, ""), nil, "general_error"},
		"not found":        {notif(waMmsRetry.MediaRetryNotification_NOT_FOUND, ""), nil, "not_found"},
		"not on phone":     {nil, fmt.Errorf("x: %w", whatsmeow.ErrMediaNotAvailableOnPhone), "not_on_phone"},
		"bad key":          {nil, fmt.Errorf("failed to decrypt notification"), "decryption_error"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := mediaRetryResult(tc.notif, tc.err); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRequestMediaReuploadSkipsNewsletterAndMissingKey(t *testing.T) {
	mycli := &MyClient{userID: "test-skip"}
	channel := &types.MessageInfo{
		MessageSource: types.MessageSource{Chat: types.NewJID("120363415307246687", types.NewsletterServer)},
		ID:            "NEWS1",
	}
	media, _ := receivedMediaOf(&waE2E.Message{ImageMessage: &waE2E.ImageMessage{MediaKey: []byte{1}}})
	if mycli.requestMediaReupload(channel, media, nil, "", true, mediaS3Config{}) {
		t.Error("channels do not accept reupload requests")
	}

	chat := &types.MessageInfo{
		MessageSource: types.MessageSource{Chat: types.NewJID("5512999999999", types.DefaultUserServer)},
		ID:            "NOKEY",
	}
	noKey, _ := receivedMediaOf(&waE2E.Message{ImageMessage: &waE2E.ImageMessage{}})
	if mycli.requestMediaReupload(chat, noKey, nil, "", true, mediaS3Config{}) {
		t.Error("without a media key the answer cannot be decrypted")
	}
}
