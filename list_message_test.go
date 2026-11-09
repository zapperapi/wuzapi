package main

import (
	"testing"

	"github.com/polymorfa/hypermeow/proto/waE2E"
)

func sampleListSections() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"title": "Bebidas",
			"rows": []map[string]interface{}{
				{"header": "", "title": "Café", "description": "200ml", "id": "cafe"},
				{"header": "", "title": "Suco", "description": "", "id": "suco"},
			},
		},
		{
			"title": "",
			"rows": []map[string]interface{}{
				{"header": "", "title": "Pão", "description": "", "id": "pao"},
			},
		},
	}
}

func TestBuildListMessage(t *testing.T) {
	msg := buildListMessage("Menu", "Escolha uma opção", "Ver opções", "rodapé", sampleListSections())

	list := msg.GetListMessage()
	if list == nil || msg.InteractiveMessage != nil || msg.ViewOnceMessage != nil {
		t.Fatalf("a lista é um ListMessage simples, sem embrulho nem native flow: %+v", msg)
	}
	if list.GetListType() != waE2E.ListMessage_SINGLE_SELECT {
		t.Errorf("ListType = %v, esperado SINGLE_SELECT", list.GetListType())
	}
	if list.GetTitle() != "Menu" || list.GetDescription() != "Escolha uma opção" ||
		list.GetButtonText() != "Ver opções" || list.GetFooterText() != "rodapé" {
		t.Errorf("textos incorretos: %+v", list)
	}
	if len(list.GetSections()) != 2 {
		t.Fatalf("seções = %d, esperado 2", len(list.GetSections()))
	}
	first := list.GetSections()[0]
	if first.GetTitle() != "Bebidas" || len(first.GetRows()) != 2 {
		t.Errorf("primeira seção incorreta: %+v", first)
	}
	row := first.GetRows()[0]
	if row.GetTitle() != "Café" || row.GetDescription() != "200ml" || row.GetRowID() != "cafe" {
		t.Errorf("primeira linha incorreta: %+v", row)
	}
	if first.GetRows()[1].Description != nil {
		t.Errorf("descrição vazia não deve ser enviada")
	}
	if list.GetSections()[1].Title != nil {
		t.Errorf("título de seção vazio não deve ser enviado")
	}
}

func TestBuildListMessageWithoutFooter(t *testing.T) {
	msg := buildListMessage("Menu", "Descrição", "Abrir", "", sampleListSections())
	if msg.GetListMessage().FooterText != nil {
		t.Errorf("sem rodapé informado, FooterText deve ficar ausente")
	}
}
