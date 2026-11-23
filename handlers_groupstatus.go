package main

// Group status.
//
// A group status is a status posted inside a group: only the participants of
// that group see it. WhatsApp sends it as a normal group message with two
// markers, confirmed in the WhatsApp Web bundle:
//   - the payload is wrapped in GroupStatusMessageV2 (receivers set
//     isGroupStatus when they unwrap it, WAWebE2EProtoParser);
//   - the stanza carries <meta is_group_status="true"> (WAWebSendMsgMetaNode).
// The server then delivers it to the participants as a <status> stanza.
//
// Kept in a dedicated file to minimise rebase conflicts against upstream.

import (
	"crypto/rand"
	"errors"
	"fmt"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/polymorfa/hypermeow/types"
)

var errGroupStatusRequiresGroup = errors.New("GroupStatus requires a group JID")

// wrapGroupStatus returns the message to send as a group status and marks the
// send request. The original message is not changed.
func wrapGroupStatus(recipient types.JID, msg *waE2E.Message, extra *whatsmeow.SendRequestExtra) (*waE2E.Message, error) {
	if recipient.Server != types.GroupServer {
		return nil, errGroupStatusRequiresGroup
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate message secret: %w", err)
	}
	if extra.Meta == nil {
		extra.Meta = &types.MsgMetaInfo{}
	}
	extra.Meta.IsGroupStatus = true
	return &waE2E.Message{
		GroupStatusMessageV2: &waE2E.FutureProofMessage{Message: msg},
		MessageContextInfo:   &waE2E.MessageContextInfo{MessageSecret: secret},
	}, nil
}
