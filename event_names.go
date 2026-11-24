package main

import (
	"fmt"
	"strings"

	"github.com/polymorfa/hypermeow/types/events"
)

// eventTypeName devolve o nome do tipo do evento sem o pacote, como
// "LabelEdit" para *events.LabelEdit. É o valor de "type" no webhook.
func eventTypeName(evt interface{}) string {
	name := fmt.Sprintf("%T", evt)
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return strings.TrimPrefix(name, "*")
}

// appStateFromFullSync diz se a ação de app-state veio da sincronização
// completa, e não de uma mudança feita em outro aparelho.
func appStateFromFullSync(evt interface{}) bool {
	switch e := evt.(type) {
	case *events.Contact:
		return e.FromFullSync
	case *events.LIDContact:
		return e.FromFullSync
	case *events.Pin:
		return e.FromFullSync
	case *events.Star:
		return e.FromFullSync
	case *events.DeleteForMe:
		return e.FromFullSync
	case *events.ClearChat:
		return e.FromFullSync
	case *events.UnarchiveChatsSetting:
		return e.FromFullSync
	case *events.UserStatusMute:
		return e.FromFullSync
	case *events.LabelEdit:
		return e.FromFullSync
	case *events.LabelAssociationChat:
		return e.FromFullSync
	case *events.LabelAssociationMessage:
		return e.FromFullSync
	case *events.QuickReply:
		return e.FromFullSync
	}
	return false
}
