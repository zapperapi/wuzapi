package main

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	whatsmeow "github.com/polymorfa/hypermeow"
)

func TestParseNewsletterJIDAcceptsIDWithOrWithoutSuffix(t *testing.T) {
	for _, value := range []string{
		"120363406995328786",
		"120363406995328786@newsletter",
		"  120363406995328786@newsletter ",
	} {
		jid, ok := parseNewsletterJID(value)
		if !ok {
			t.Errorf("%q was rejected", value)
			continue
		}
		if jid.String() != "120363406995328786@newsletter" {
			t.Errorf("%q parsed as %q", value, jid)
		}
	}
}

func TestParseNewsletterJIDRejectsOtherJIDs(t *testing.T) {
	for _, value := range []string{
		"",
		"   ",
		"120363406995328786@g.us",
		"5512991982175@s.whatsapp.net",
		"canal@newsletter",
		"@newsletter",
		"120363406995328786:2@newsletter",
	} {
		if jid, ok := parseNewsletterJID(value); ok {
			t.Errorf("%q was accepted as %q", value, jid)
		}
	}
}

func TestNewsletterErrorStatus(t *testing.T) {
	notFound := fmt.Errorf("follow: %w", whatsmeow.ErrNewsletterNotFound)
	if got := newsletterErrorStatus(notFound); got != http.StatusNotFound {
		t.Errorf("not found status = %d, want %d", got, http.StatusNotFound)
	}
	for _, err := range []error{
		whatsmeow.ErrNewsletterSuspended,
		errors.New("graphql error: Not Allowed"),
	} {
		if got := newsletterErrorStatus(err); got != http.StatusInternalServerError {
			t.Errorf("status for %v = %d, want %d", err, got, http.StatusInternalServerError)
		}
	}
}

func strPtr(value string) *string { return &value }

func TestBuildUpdateNewsletterParamsKeepsOmittedFieldsUnchanged(t *testing.T) {
	params, err := buildUpdateNewsletterParams(updateNewsletterStruct{Name: strPtr("  Novo nome ")})
	if err != nil {
		t.Fatal(err)
	}
	if params.Name == nil || *params.Name != "Novo nome" {
		t.Errorf("name = %v, want trimmed name", params.Name)
	}
	if params.Description != nil || params.Picture != nil {
		t.Errorf("omitted fields were set: %#v", params)
	}
}

func TestBuildUpdateNewsletterParamsClearsDescriptionAndPicture(t *testing.T) {
	params, err := buildUpdateNewsletterParams(updateNewsletterStruct{Description: strPtr(""), Image: strPtr("")})
	if err != nil {
		t.Fatal(err)
	}
	if params.Description == nil || *params.Description != "" {
		t.Errorf("description = %v, want an empty string", params.Description)
	}
	if params.Picture == nil || len(*params.Picture) != 0 {
		t.Errorf("picture = %v, want an empty slice", params.Picture)
	}
}

func TestBuildUpdateNewsletterParamsDecodesJPEG(t *testing.T) {
	params, err := buildUpdateNewsletterParams(updateNewsletterStruct{Image: strPtr("data:image/jpeg;base64,/9j/4AAQ")})
	if err != nil {
		t.Fatal(err)
	}
	if params.Picture == nil || len(*params.Picture) != 6 || (*params.Picture)[0] != 0xFF {
		t.Errorf("picture = %v, want the decoded JPEG bytes", params.Picture)
	}
}

func TestBuildUpdateNewsletterParamsRejectsInvalidBodies(t *testing.T) {
	tests := map[string]updateNewsletterStruct{
		"nothing to change": {},
		"empty name":        {Name: strPtr("   ")},
		"not a data url":    {Image: strPtr("/9j/4AAQ")},
		"png image":         {Image: strPtr("data:image/png;base64,iVBORw0KGgo=")},
		"broken base64":     {Image: strPtr("data:image/jpeg;base64,@@@")},
	}
	for name, body := range tests {
		if _, err := buildUpdateNewsletterParams(body); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
