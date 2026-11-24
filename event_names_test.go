package main

import (
	"testing"

	"github.com/polymorfa/hypermeow/types/events"
)

func TestEventTypeName(t *testing.T) {
	cases := map[string]interface{}{
		"LabelEdit":            &events.LabelEdit{},
		"LabelAssociationChat": &events.LabelAssociationChat{},
		"Contact":              &events.Contact{},
		"CallReject":           &events.CallReject{},
	}
	for want, evt := range cases {
		if got := eventTypeName(evt); got != want {
			t.Errorf("eventTypeName(%T) = %q, want %q", evt, got, want)
		}
	}
}

func TestAppStateFromFullSync(t *testing.T) {
	if !appStateFromFullSync(&events.Contact{FromFullSync: true}) {
		t.Error("Contact com FromFullSync deve ser full sync")
	}
	if appStateFromFullSync(&events.Pin{}) {
		t.Error("Pin sem FromFullSync não é full sync")
	}
	if appStateFromFullSync(&events.PushName{}) {
		t.Error("evento fora do app-state nunca é full sync")
	}
}
