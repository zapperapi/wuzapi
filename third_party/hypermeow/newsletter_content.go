// Enquete, quiz e pergunta em canal. O formato vem dos módulos
// WASmaxMessagePublishNewsletterRPC, WAWebPollsGeneratePollCreationMessageProto
// e WAWebE2EProtoGenerator do WhatsApp Web 2.3000.1055901559.
// Ver WUZAPI_PATCHES.md, "Enquete, quiz e pergunta em canal".

package whatsmeow

import (
	"errors"

	"google.golang.org/protobuf/proto"

	waBinary "github.com/polymorfa/hypermeow/binary"
	"github.com/polymorfa/hypermeow/proto/waE2E"
)

// getPollCreation devolve a criação de enquete da mensagem, em qualquer das
// versões que os clientes usam.
func getPollCreation(msg *waE2E.Message) *waE2E.PollCreationMessage {
	switch {
	case msg == nil:
		return nil
	case msg.PollCreationMessage != nil:
		return msg.PollCreationMessage
	case msg.PollCreationMessageV2 != nil:
		return msg.PollCreationMessageV2
	case msg.PollCreationMessageV3 != nil:
		return msg.PollCreationMessageV3
	case msg.PollCreationMessageV5 != nil:
		return msg.PollCreationMessageV5
	case msg.PollCreationMessageV6 != nil:
		return msg.PollCreationMessageV6
	default:
		return nil
	}
}

// newsletterMetaNode monta o <meta> que acompanha a publicação em canal.
//
//   - enquete e quiz: <meta polltype="creation" contenttype="text"|"image">
//   - pergunta: <meta questiontype="question">
//
// As outras mensagens não levam <meta>.
func newsletterMetaNode(msg *waE2E.Message) *waBinary.Node {
	if msg == nil {
		return nil
	}
	if msg.QuestionMessage != nil {
		return &waBinary.Node{Tag: "meta", Attrs: waBinary.Attrs{"questiontype": "question"}}
	}
	if poll := getPollCreation(msg); poll != nil {
		contentType := "text"
		if poll.GetPollContentType() == waE2E.PollContentType_IMAGE {
			contentType = "image"
		}
		return &waBinary.Node{Tag: "meta", Attrs: waBinary.Attrs{
			"polltype":    "creation",
			"contenttype": contentType,
		}}
	}
	return nil
}

func newsletterPollOptions(optionNames []string) []*waE2E.PollCreationMessage_Option {
	options := make([]*waE2E.PollCreationMessage_Option, len(optionNames))
	for i, option := range optionNames {
		options[i] = &waE2E.PollCreationMessage_Option{OptionName: proto.String(option)}
	}
	return options
}

// BuildNewsletterPoll builds a poll to publish in a channel.
//
// Unlike BuildPollCreation, it has no message secret: channel messages are not
// encrypted. A single-choice poll uses PollCreationMessageV3, as the WhatsApp
// clients do.
func BuildNewsletterPoll(name string, optionNames []string, singleChoice bool) *waE2E.Message {
	poll := &waE2E.PollCreationMessage{
		Name:                   proto.String(name),
		Options:                newsletterPollOptions(optionNames),
		SelectableOptionsCount: proto.Uint32(0),
		PollContentType:        waE2E.PollContentType_TEXT.Enum(),
		PollType:               waE2E.PollType_POLL.Enum(),
	}
	if singleChoice {
		poll.SelectableOptionsCount = proto.Uint32(1)
		return &waE2E.Message{PollCreationMessageV3: poll}
	}
	return &waE2E.Message{PollCreationMessage: poll}
}

// ErrInvalidQuizAnswer is returned when the correct answer of a quiz is not one of its options.
var ErrInvalidQuizAnswer = errors.New("the correct answer must be the index of one of the quiz options")

// BuildNewsletterQuiz builds a quiz to publish in a channel. A quiz is a
// single-choice poll with one correct option.
func BuildNewsletterQuiz(name string, optionNames []string, correctOption int) (*waE2E.Message, error) {
	if correctOption < 0 || correctOption >= len(optionNames) {
		return nil, ErrInvalidQuizAnswer
	}
	options := newsletterPollOptions(optionNames)
	return &waE2E.Message{PollCreationMessageV3: &waE2E.PollCreationMessage{
		Name:                   proto.String(name),
		Options:                options,
		SelectableOptionsCount: proto.Uint32(1),
		PollContentType:        waE2E.PollContentType_TEXT.Enum(),
		PollType:               waE2E.PollType_QUIZ.Enum(),
		CorrectAnswer:          &waE2E.PollCreationMessage_Option{OptionName: options[correctOption].OptionName},
	}}, nil
}

// BuildNewsletterQuestion builds a question to publish in a channel: a text
// message the followers can answer. The text goes in an ExtendedTextMessage
// marked with ContextInfo.IsQuestion and wrapped in QuestionMessage.
func BuildNewsletterQuestion(text string) *waE2E.Message {
	return &waE2E.Message{QuestionMessage: &waE2E.FutureProofMessage{
		Message: &waE2E.Message{ExtendedTextMessage: &waE2E.ExtendedTextMessage{
			Text:        proto.String(text),
			ContextInfo: &waE2E.ContextInfo{IsQuestion: proto.Bool(true)},
		}},
	}}
}
