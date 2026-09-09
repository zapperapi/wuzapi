package meowcaller

import (
	"github.com/rs/zerolog"
	"wuzapi/internal/meowcaller/diag"
)

// Option configures optional, non-behavioral aspects of the call/media types —
// currently the diagnostic logger. The zero configuration logs nothing.
type Option func(*config)

type config struct {
	log  zerolog.Logger
	diag *diag.Recorder
	// Negative on purpose: the zero value must mean upstream behavior, in struct
	// literals as much as through resolveConfig. See WithTypedCallAcks.
	suppressTypedCallAcks bool
}

func resolveConfig(opts []Option) config {
	c := config{log: zerolog.Nop()}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// WithLogger sets the zerolog logger for debug/trace diagnostics. The library never
// configures logging itself; without this option the types are silent at zero cost.
// Pass the logger from a context, e.g. WithLogger(*zerolog.Ctx(ctx)).
func WithLogger(l zerolog.Logger) Option {
	return func(c *config) { c.log = l }
}

// WithDiagnostics attaches a developer-only *diag.Recorder that dumps exact,
// per-category call diagnostics (including raw secrets and media) to JSONL files.
// This is an opt-in maintainer carve-out from the library's sanitized logging and
// must never be enabled in production. Without it the recorder is nil and every
// diag emit is a no-op at zero cost.
func WithDiagnostics(rec *diag.Recorder) Option {
	return func(c *config) { c.diag = rec }
}

// WithTypedCallAcks controls whether the engine answers inbound <call> stanzas with
// its own typed <ack>.
//
// FORK PATCH (see UPSTREAM.md, patch 3). Upstream always acks, because it also drops
// the <call> node before the underlying library can see it. This fork does not drop
// <call> — it lets hypermeow's handleCallEvent run, so the events the platform
// already forwards to customers keep being emitted unchanged. With both paths live,
// acking here too would answer the peer twice.
//
// Disable it to leave hypermeow as the single acker. The typed ack only matters for
// the mid-call video upgrade and group-call control stanzas; a voice-only 1:1
// integration never needs it.
//
// Defaults to enabled, so the fork's divergence is always opt-in and every upstream
// test keeps describing real behavior.
func WithTypedCallAcks(enabled bool) Option {
	return func(c *config) { c.suppressTypedCallAcks = !enabled }
}
