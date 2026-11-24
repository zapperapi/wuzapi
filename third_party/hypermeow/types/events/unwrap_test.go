package events

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/polymorfa/hypermeow/proto/waCommon"
	"github.com/polymorfa/hypermeow/proto/waE2E"
)

// Formato do WhatsApp Web ao mandar a versão HD de uma foto
// (WAWebE2EProtoGenerator, função $): a mídia vai dentro de
// associatedChildMessage e o vínculo fica no messageContextInfo de fora.
func TestUnwrapRawAssociatedChild(t *testing.T) {
	association := &waE2E.MessageAssociation{
		AssociationType: waE2E.MessageAssociation_HD_IMAGE_DUAL_UPLOAD.Enum(),
		ParentMessageKey: &waCommon.MessageKey{
			RemoteJID: proto.String("5512999999999@s.whatsapp.net"),
			FromMe:    proto.Bool(false),
			ID:        proto.String("3EB0PARENT"),
		},
	}
	hd := &waE2E.ImageMessage{Mimetype: proto.String("image/jpeg")}

	tests := map[string]*waE2E.Message{
		"plain": {
			AssociatedChildMessage: &waE2E.FutureProofMessage{Message: &waE2E.Message{ImageMessage: hd}},
			MessageContextInfo:     &waE2E.MessageContextInfo{MessageAssociation: association},
		},
		"inside ephemeral": {
			EphemeralMessage: &waE2E.FutureProofMessage{Message: &waE2E.Message{
				AssociatedChildMessage: &waE2E.FutureProofMessage{Message: &waE2E.Message{ImageMessage: hd}},
				MessageContextInfo:     &waE2E.MessageContextInfo{MessageAssociation: association},
			}},
		},
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			evt := (&Message{RawMessage: raw}).UnwrapRaw()
			if !evt.IsAssociatedChild {
				t.Error("IsAssociatedChild = false")
			}
			if evt.Message.GetImageMessage() != hd {
				t.Fatalf("message = %v, want the HD image", evt.Message)
			}
			got := evt.Message.GetMessageContextInfo().GetMessageAssociation()
			if got.GetAssociationType() != waE2E.MessageAssociation_HD_IMAGE_DUAL_UPLOAD ||
				got.GetParentMessageKey().GetID() != "3EB0PARENT" {
				t.Errorf("association = %v", got)
			}
		})
	}
}

// O filho que chega sem o invólucro (o Web só embrulha quando o ABProp
// wa_web_wrap_associated_child_message_enabled está ligado) não muda.
func TestUnwrapRawUnwrappedChild(t *testing.T) {
	raw := &waE2E.Message{
		VideoMessage: &waE2E.VideoMessage{},
		MessageContextInfo: &waE2E.MessageContextInfo{MessageAssociation: &waE2E.MessageAssociation{
			AssociationType: waE2E.MessageAssociation_MOTION_PHOTO.Enum(),
		}},
	}
	evt := (&Message{RawMessage: raw}).UnwrapRaw()
	if evt.IsAssociatedChild || evt.Message != raw {
		t.Errorf("IsAssociatedChild = %t, message changed = %t", evt.IsAssociatedChild, evt.Message != raw)
	}
}
