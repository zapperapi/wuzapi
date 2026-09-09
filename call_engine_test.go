package main

import "testing"

// The outcome table is the published vocabulary of FR-033. These cases pin the six
// outcomes the spec requires the customer to be able to distinguish.
func TestResolveCallOutcome(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   CallOutcome
	}{
		// Ended by us, through the API.
		{"hangup", CallOutcomeTerminatedByBusiness},
		{"rejected", CallOutcomeRejected},

		// Ended by the peer or the network.
		{"reject", CallOutcomeRejected},
		{"decline", CallOutcomeRejected},
		{"timeout", CallOutcomeMissed},
		{"busy", CallOutcomeUnavailable},
		{"bye", CallOutcomeCompleted},
		{"accept_elsewhere", CallOutcomeCompleted},
		{"connection-error", CallOutcomeFailed},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			got, ok := resolveCallOutcome(tc.reason)
			if !ok {
				t.Fatalf("reason %q is not covered by the outcome table", tc.reason)
			}
			if got != tc.want {
				t.Fatalf("outcome = %q, want %q", got, tc.want)
			}
		})
	}
}

// Any signaling failure is a failure, whatever the server's code. Matching by prefix
// is what makes a code we have never seen classify correctly instead of falling
// through as unknown.
func TestResolveCallOutcomeServerErrors(t *testing.T) {
	for _, reason := range []string{"server:487", "server:503", "server:some-new-code"} {
		got, ok := resolveCallOutcome(reason)
		if !ok || got != CallOutcomeFailed {
			t.Fatalf("reason %q: outcome = %q (mapped=%v), want FAILED", reason, got, ok)
		}
	}
}

// An unmapped reason must yield no outcome rather than a guessed one: the customer
// receives the raw reason, and the gap is logged so the table grows from what
// production emits.
func TestResolveCallOutcomeLeavesUnknownReasonsUnmapped(t *testing.T) {
	for _, reason := range []string{"", "some-reason-nobody-has-seen"} {
		if got, ok := resolveCallOutcome(reason); ok {
			t.Fatalf("reason %q was mapped to %q; unknown reasons must stay unmapped", reason, got)
		}
	}
}
