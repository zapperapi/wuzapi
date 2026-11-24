package main

import (
	"context"
	"errors"
	"testing"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/proto/waE2E"
)

func intPtr(value int) *int    { return &value }
func boolPtr(value bool) *bool { return &value }

func TestParseNewsletterFollowerCount(t *testing.T) {
	for value, want := range map[string]int{"": 100, "1": 1, "250": 250, "1000": 1000} {
		got, err := parseNewsletterFollowerCount(value)
		if err != nil || got != want {
			t.Errorf("count %q = %d, %v; want %d", value, got, err, want)
		}
	}
	for _, value := range []string{"0", "-5", "1001", "abc", "1.5"} {
		if _, err := parseNewsletterFollowerCount(value); err == nil {
			t.Errorf("count %q: expected an error", value)
		}
	}
}

func TestResolveNewsletterUserLIDKeepsLIDAndRejectsOtherJIDs(t *testing.T) {
	lid, err := resolveNewsletterUserLID(context.Background(), nil, "123456789012345@lid")
	if err != nil || lid.String() != "123456789012345@lid" {
		t.Fatalf("lid = %v, err = %v", lid, err)
	}
	for _, value := range []string{"", "   ", "120363000000000000@g.us", "120363406995328786@newsletter"} {
		_, err := resolveNewsletterUserLID(context.Background(), nil, value)
		var badRequest newsletterBadRequest
		if !errors.As(err, &badRequest) {
			t.Errorf("user %q: error = %v, want a bad request", value, err)
		}
	}
}

func TestValidateNewsletterPin(t *testing.T) {
	if err := validateNewsletterPin(newsletterPinStruct{ServerIDs: []int{142, 143}, Pin: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]newsletterPinStruct{
		"no pin":         {ServerIDs: []int{142}},
		"no server ids":  {Pin: boolPtr(false)},
		"zero server id": {ServerIDs: []int{142, 0}, Pin: boolPtr(true)},
	} {
		if err := validateNewsletterPin(body); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestValidateNewsletterInsightMetrics(t *testing.T) {
	valid := []whatsmeow.NewsletterInsightMetric{
		{ID: 1, Type: whatsmeow.NewsletterInsightFollowers, GroupBy: whatsmeow.NewsletterInsightGroupBy{NumberOfDays: 30}},
		{ID: 2, Type: whatsmeow.NewsletterInsightFollows, GroupBy: whatsmeow.NewsletterInsightGroupBy{NumberOfDays: 1}},
	}
	if err := validateNewsletterInsightMetrics(valid); err != nil {
		t.Fatal(err)
	}
	for name, metrics := range map[string][]whatsmeow.NewsletterInsightMetric{
		"empty":       nil,
		"no type":     {{ID: 1, GroupBy: whatsmeow.NewsletterInsightGroupBy{NumberOfDays: 30}}},
		"no days":     {{ID: 1, Type: whatsmeow.NewsletterInsightFollowers}},
		"repeated id": {valid[0], valid[0]},
	} {
		if err := validateNewsletterInsightMetrics(metrics); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestBuildNewsletterPollMessage(t *testing.T) {
	poll, err := buildNewsletterPollMessage(newsletterPollStruct{Name: " Qual dia? ", Options: []string{" Segunda ", "Terça"}})
	if err != nil {
		t.Fatal(err)
	}
	if poll.GetPollCreationMessage().GetName() != "Qual dia?" || poll.GetPollCreationMessage().Options[0].GetOptionName() != "Segunda" {
		t.Errorf("poll = %#v", poll.GetPollCreationMessage())
	}

	single, err := buildNewsletterPollMessage(newsletterPollStruct{Name: "?", Options: []string{"a", "b"}, SingleChoice: true})
	if err != nil || single.GetPollCreationMessageV3().GetSelectableOptionsCount() != 1 {
		t.Errorf("single choice = %#v, err = %v", single, err)
	}

	quiz, err := buildNewsletterPollMessage(newsletterPollStruct{Name: "?", Options: []string{"a", "b", "c"}, CorrectOption: intPtr(2)})
	if err != nil {
		t.Fatal(err)
	}
	if quiz.GetPollCreationMessageV3().GetPollType() != waE2E.PollType_QUIZ || quiz.GetPollCreationMessageV3().GetCorrectAnswer().GetOptionName() != "c" {
		t.Errorf("quiz = %#v", quiz.GetPollCreationMessageV3())
	}
}

func TestBuildNewsletterPollMessageRejectsInvalidBodies(t *testing.T) {
	many := make([]string, 13)
	for i := range many {
		many[i] = string(rune('a' + i))
	}
	for name, body := range map[string]newsletterPollStruct{
		"no name":             {Options: []string{"a", "b"}},
		"one option":          {Name: "?", Options: []string{"a"}},
		"too many options":    {Name: "?", Options: many},
		"empty option":        {Name: "?", Options: []string{"a", "  "}},
		"repeated option":     {Name: "?", Options: []string{"a", " a "}},
		"answer out of range": {Name: "?", Options: []string{"a", "b"}, CorrectOption: intPtr(2)},
		"negative answer":     {Name: "?", Options: []string{"a", "b"}, CorrectOption: intPtr(-1)},
	} {
		if _, err := buildNewsletterPollMessage(body); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
