package main

import (
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"google.golang.org/protobuf/proto"
)

// buildListMessage monta a lista como ListMessage (listType SINGLE_SELECT), que é como
// o cliente oficial a representa (WAWebParseListMessageProto, no WhatsApp Web). As seções
// vêm no mesmo formato usado pelo caminho native_flow: title e rows[] com title,
// description e id.
func buildListMessage(title, description, buttonText, footer string, sections []map[string]interface{}) *waE2E.Message {
	list := &waE2E.ListMessage{
		Title:       proto.String(title),
		Description: proto.String(description),
		ButtonText:  proto.String(buttonText),
		ListType:    waE2E.ListMessage_SINGLE_SELECT.Enum(),
	}
	if footer != "" {
		list.FooterText = proto.String(footer)
	}
	for _, section := range sections {
		built := &waE2E.ListMessage_Section{}
		if sectionTitle, ok := section["title"].(string); ok && sectionTitle != "" {
			built.Title = proto.String(sectionTitle)
		}
		rows, _ := section["rows"].([]map[string]interface{})
		for _, row := range rows {
			item := &waE2E.ListMessage_Row{}
			if v, ok := row["title"].(string); ok {
				item.Title = proto.String(v)
			}
			if v, ok := row["description"].(string); ok && v != "" {
				item.Description = proto.String(v)
			}
			if v, ok := row["id"].(string); ok {
				item.RowID = proto.String(v)
			}
			built.Rows = append(built.Rows, item)
		}
		list.Sections = append(list.Sections, built)
	}
	return &waE2E.Message{ListMessage: list}
}
