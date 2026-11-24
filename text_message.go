package main

import (
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"google.golang.org/protobuf/proto"
)

// newTextMessage builds the text message of /chat/send/text. The link preview
// fields are set only when the text has a link to preview (matchedURL): the
// hypermeow classifies a message with Title as mediatype="url", and the
// WhatsApp Web only does that when matchedText is not empty
// (WAWebE2EProtoUtils). Before, every text went out as a link.
func newTextMessage(body, matchedURL string, og openGraphResult) *waE2E.Message {
	text := &waE2E.ExtendedTextMessage{Text: proto.String(body)}
	if matchedURL != "" {
		text.MatchedText = proto.String(matchedURL)
		text.Title = proto.String(og.Title)
		text.Description = proto.String(og.Description)
		text.JPEGThumbnail = og.ImageData
	}
	return &waE2E.Message{ExtendedTextMessage: text}
}

// simplifyTextMessage sends a plain text as Conversation, as the WhatsApp Web
// does when there is no quote, mention, forward, expiration nor link preview
// (WAWebGenerateChatMessageProto). Any other text stays ExtendedTextMessage.
func simplifyTextMessage(msg *waE2E.Message) *waE2E.Message {
	text := msg.GetExtendedTextMessage()
	if text == nil || text.ContextInfo != nil || text.MatchedText != nil || text.Title != nil ||
		len(text.JPEGThumbnail) > 0 || text.ThumbnailDirectPath != nil {
		return msg
	}
	return &waE2E.Message{Conversation: text.Text}
}
