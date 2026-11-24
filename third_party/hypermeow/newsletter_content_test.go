package whatsmeow

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/polymorfa/hypermeow/proto/waE2E"
)

func TestBuildNewsletterPollMultipleChoice(t *testing.T) {
	msg := BuildNewsletterPoll("Qual dia?", []string{"Segunda", "Terça"}, false)
	poll := msg.GetPollCreationMessage()
	if poll == nil || msg.PollCreationMessageV3 != nil {
		t.Fatal("multiple choice must use PollCreationMessage (V1)")
	}
	if poll.GetName() != "Qual dia?" || len(poll.Options) != 2 || poll.Options[1].GetOptionName() != "Terça" {
		t.Errorf("poll = %#v", poll)
	}
	if poll.GetSelectableOptionsCount() != 0 || poll.GetPollType() != waE2E.PollType_POLL || poll.GetPollContentType() != waE2E.PollContentType_TEXT {
		t.Errorf("poll settings = count %d, type %v, content %v", poll.GetSelectableOptionsCount(), poll.GetPollType(), poll.GetPollContentType())
	}
	if msg.MessageContextInfo != nil {
		t.Error("a channel poll must not carry a message secret")
	}
}

func TestBuildNewsletterPollSingleChoiceUsesV3(t *testing.T) {
	msg := BuildNewsletterPoll("Qual dia?", []string{"Segunda", "Terça"}, true)
	poll := msg.GetPollCreationMessageV3()
	if poll == nil || msg.PollCreationMessage != nil {
		t.Fatal("single choice must use PollCreationMessageV3")
	}
	if poll.GetSelectableOptionsCount() != 1 {
		t.Errorf("selectable options = %d, want 1", poll.GetSelectableOptionsCount())
	}
}

func TestBuildNewsletterQuiz(t *testing.T) {
	msg, err := BuildNewsletterQuiz("Capital do Brasil?", []string{"Rio", "Brasília", "Salvador"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	quiz := msg.GetPollCreationMessageV3()
	if quiz == nil {
		t.Fatal("a quiz must use PollCreationMessageV3")
	}
	if quiz.GetPollType() != waE2E.PollType_QUIZ || quiz.GetSelectableOptionsCount() != 1 {
		t.Errorf("quiz settings = type %v, count %d", quiz.GetPollType(), quiz.GetSelectableOptionsCount())
	}
	if quiz.GetCorrectAnswer().GetOptionName() != "Brasília" {
		t.Errorf("correct answer = %q", quiz.GetCorrectAnswer().GetOptionName())
	}
	if msg.MessageContextInfo != nil {
		t.Error("a channel quiz must not carry a message secret")
	}
	for _, index := range []int{-1, 3} {
		if _, err := BuildNewsletterQuiz("?", []string{"a", "b", "c"}, index); !errors.Is(err, ErrInvalidQuizAnswer) {
			t.Errorf("index %d: error = %v, want %v", index, err, ErrInvalidQuizAnswer)
		}
	}
}

func TestBuildNewsletterQuestion(t *testing.T) {
	msg := BuildNewsletterQuestion("O que vocês querem ver?")
	inner := msg.GetQuestionMessage().GetMessage()
	if inner.GetExtendedTextMessage().GetText() != "O que vocês querem ver?" {
		t.Fatalf("question text = %q", inner.GetExtendedTextMessage().GetText())
	}
	if !inner.GetExtendedTextMessage().GetContextInfo().GetIsQuestion() {
		t.Error("the question must be marked with ContextInfo.IsQuestion")
	}
}

func TestNewsletterMetaNode(t *testing.T) {
	quiz, _ := BuildNewsletterQuiz("?", []string{"a", "b"}, 0)
	imagePoll := BuildNewsletterPoll("?", []string{"a", "b"}, true)
	imagePoll.PollCreationMessageV3.PollContentType = waE2E.PollContentType_IMAGE.Enum()

	tests := []struct {
		name string
		msg  *waE2E.Message
		want map[string]any
	}{
		{"multiple choice poll", BuildNewsletterPoll("?", []string{"a", "b"}, false), map[string]any{"polltype": "creation", "contenttype": "text"}},
		{"single choice poll", BuildNewsletterPoll("?", []string{"a", "b"}, true), map[string]any{"polltype": "creation", "contenttype": "text"}},
		{"quiz uses the poll creation type", quiz, map[string]any{"polltype": "creation", "contenttype": "text"}},
		{"image poll", imagePoll, map[string]any{"polltype": "creation", "contenttype": "image"}},
		{"question", BuildNewsletterQuestion("?"), map[string]any{"questiontype": "question"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := newsletterMetaNode(tc.msg)
			if node == nil || node.Tag != "meta" {
				t.Fatalf("node = %#v, want a <meta>", node)
			}
			if len(node.Attrs) != len(tc.want) {
				t.Fatalf("attrs = %#v, want %#v", node.Attrs, tc.want)
			}
			for key, value := range tc.want {
				if node.Attrs[key] != value {
					t.Errorf("attr %s = %v, want %v", key, node.Attrs[key], value)
				}
			}
		})
	}

	for name, msg := range map[string]*waE2E.Message{
		"text":  {Conversation: proto.String("oi")},
		"image": {ImageMessage: &waE2E.ImageMessage{}},
		"nil":   nil,
	} {
		if node := newsletterMetaNode(msg); node != nil {
			t.Errorf("%s: unexpected <meta> %#v", name, node)
		}
	}
}

func TestMessageTypeForPollVersionsAndQuestions(t *testing.T) {
	poll := &waE2E.PollCreationMessage{Name: proto.String("?")}
	for name, msg := range map[string]*waE2E.Message{
		"v1": {PollCreationMessage: poll},
		"v2": {PollCreationMessageV2: poll},
		"v3": {PollCreationMessageV3: poll},
		"v5": {PollCreationMessageV5: poll},
		"v6": {PollCreationMessageV6: poll},
	} {
		if got := getTypeFromMessage(msg); got != "poll" {
			t.Errorf("poll %s: type = %q, want poll", name, got)
		}
	}

	if got := getTypeFromMessage(BuildNewsletterQuestion("?")); got != "text" {
		t.Errorf("text question: type = %q, want text", got)
	}
	if got := getMediaTypeFromMessage(BuildNewsletterQuestion("?")); got != "" {
		t.Errorf("text question: mediatype = %q, want empty", got)
	}

	imageQuestion := &waE2E.Message{QuestionMessage: &waE2E.FutureProofMessage{
		Message: &waE2E.Message{ImageMessage: &waE2E.ImageMessage{}},
	}}
	if got := getTypeFromMessage(imageQuestion); got != "media" {
		t.Errorf("image question: type = %q, want media", got)
	}
	if got := getMediaTypeFromMessage(imageQuestion); got != "image" {
		t.Errorf("image question: mediatype = %q, want image", got)
	}
}
