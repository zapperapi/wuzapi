package main

import (
	"testing"

	"github.com/polymorfa/hypermeow/proto/waE2E"
	"google.golang.org/protobuf/proto"
)

func TestPlainTextIsSentAsConversation(t *testing.T) {
	msg := simplifyTextMessage(newTextMessage("Post de teste", "", openGraphResult{}))
	if msg.GetConversation() != "Post de teste" || msg.ExtendedTextMessage != nil {
		t.Fatalf("message = %#v, want a Conversation", msg)
	}
}

func TestTextWithLinkPreviewKeepsExtendedText(t *testing.T) {
	og := openGraphResult{Title: "Exemplo", Description: "Descrição", ImageData: []byte{0xff, 0xd8}}
	msg := simplifyTextMessage(newTextMessage("Veja https://exemplo.com", "https://exemplo.com", og))
	text := msg.GetExtendedTextMessage()
	if text == nil {
		t.Fatal("a text with link preview must stay ExtendedTextMessage")
	}
	if text.GetMatchedText() != "https://exemplo.com" || text.GetTitle() != "Exemplo" || text.GetDescription() != "Descrição" || len(text.JPEGThumbnail) != 2 {
		t.Errorf("preview fields = %#v", text)
	}
}

func TestTextWithLinkWithoutMetadataStaysLink(t *testing.T) {
	msg := simplifyTextMessage(newTextMessage("Veja https://exemplo.com", "https://exemplo.com", openGraphResult{}))
	text := msg.GetExtendedTextMessage()
	if text == nil || text.Title == nil || text.GetMatchedText() != "https://exemplo.com" {
		t.Fatalf("message = %#v, want ExtendedTextMessage with matchedText", msg)
	}
}

func TestPlainTextHasNoPreviewFields(t *testing.T) {
	text := newTextMessage("Oi", "", openGraphResult{}).GetExtendedTextMessage()
	if text.MatchedText != nil || text.Title != nil || text.Description != nil || text.JPEGThumbnail != nil {
		t.Fatalf("plain text has preview fields: %#v", text)
	}
}

func TestTextWithContextInfoKeepsExtendedText(t *testing.T) {
	for name, info := range map[string]*waE2E.ContextInfo{
		"quote":      {StanzaID: proto.String("3EB0"), QuotedMessage: &waE2E.Message{Conversation: proto.String("")}},
		"mention":    {MentionedJID: []string{"5511999999999@s.whatsapp.net"}},
		"forwarded":  {IsForwarded: proto.Bool(true)},
		"expiration": {Expiration: proto.Uint32(86400)},
	} {
		msg := newTextMessage("Oi", "", openGraphResult{})
		msg.ExtendedTextMessage.ContextInfo = info
		if simplifyTextMessage(msg).GetExtendedTextMessage() == nil {
			t.Errorf("%s: the text must stay ExtendedTextMessage", name)
		}
	}
}
