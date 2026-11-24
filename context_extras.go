package main

import (
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/polymorfa/hypermeow/types"
	"google.golang.org/protobuf/proto"
)

// mentionAllJIDs devolve os participantes do grupo no formato de
// ContextInfo.MentionedJID, sem a própria conta. É o "mencionar todos" do
// wuzapi: o WA Web tem o @all (nonJidMentions = MENTION_ALL), mas só oferece
// para admin ou em grupo abaixo de `admin_only_mention_everyone_group_size`
// (WAWebMentionPickerPlugin), e cliente antigo não o reconhece. A lista de
// participantes vale em qualquer grupo e em qualquer versão.
func mentionAllJIDs(info *types.GroupInfo, own ...types.JID) []string {
	if info == nil {
		return nil
	}
	skip := make(map[types.JID]struct{}, len(own))
	for _, jid := range own {
		if !jid.IsEmpty() {
			skip[jid.ToNonAD()] = struct{}{}
		}
	}
	jids := make([]string, 0, len(info.Participants))
	for _, p := range info.Participants {
		if _, ok := skip[p.JID.ToNonAD()]; ok {
			continue
		}
		if _, ok := skip[p.LID.ToNonAD()]; ok && !p.LID.IsEmpty() {
			continue
		}
		if _, ok := skip[p.PhoneNumber.ToNonAD()]; ok && !p.PhoneNumber.IsEmpty() {
			continue
		}
		jids = append(jids, p.JID.ToNonAD().String())
	}
	return jids
}

// applyExpiration copia ContextInfo.Expiration do corpo da requisição para a
// mensagem. O WA Web põe o temporizador do chat em contextInfo.expiration
// (WAWebE2EProtoGenerator); sem o campo, a mensagem sai permanente mesmo em
// chat temporário. Zero ou ausente não muda nada.
func applyExpiration(dst **waE2E.ContextInfo, expiration *uint32) {
	if expiration == nil || *expiration == 0 {
		return
	}
	if *dst == nil {
		*dst = &waE2E.ContextInfo{}
	}
	(*dst).Expiration = proto.Uint32(*expiration)
}
