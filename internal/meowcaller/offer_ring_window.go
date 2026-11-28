package meowcaller

import (
	"time"

	waBinary "github.com/polymorfa/hypermeow/binary"
)

// Janela de toque de uma oferta de chamada 1:1, igual à do WhatsApp Web
// 2.3000.1056475087 (módulo WAWebVoipCallOfferRingWindow, canCallOfferStillRing).
// Uma oferta que ficou esse tempo na fila do servidor (atributo "e" do <call>)
// já não toca no cliente oficial: a chamada acabou ou está para acabar.
const offerRingWindow = 90 * time.Second

// Motivos do filho <silence reason="..."> com que o cliente oficial não toca.
var offerSilenceReasons = map[string]struct{}{
	"added_as_link_creator":      {},
	"added_for_device_switching": {},
	"group_chat_add":             {},
	"group_setting":              {},
	"lightweight":                {},
	"privacy":                    {},
	"scheduled":                  {},
	"vc_init":                    {},
	"vc_wave":                    {},
	"vc_wave_all":                {},
	"wave":                       {},
}

// offerSkipReason diz por que uma oferta 1:1 não deve tocar. Devolve "" quando
// a oferta pode tocar. queued é o tempo que a oferta ficou na fila do servidor.
func offerSkipReason(offer *waBinary.Node, queued time.Duration) string {
	if offer == nil {
		return ""
	}
	if silenceNode, ok := offer.GetOptionalChildByTag("silence"); ok {
		reason := silenceNode.AttrGetter().OptionalString("reason")
		if _, silenced := offerSilenceReasons[reason]; silenced {
			return "silenced:" + reason
		}
	}
	if queued >= offerRingWindow {
		return "expired"
	}
	return ""
}
