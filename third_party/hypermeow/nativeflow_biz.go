package whatsmeow

// Patch local do wuzapi (ver WUZAPI_PATCHES.md).
//
// O cliente oficial do WhatsApp não manda no nó <biz> o nome do botão, e sim o
// nome do fluxo que ele deriva dele (WAWebBizTemplateAndInteractiveMessagesUtils,
// função getNativeFlowNameByButtonName, no WhatsApp Web 2.3000.1053682356).
// Quase todos os nomes coincidem, e as exceções são as quatro de nativeFlowNames.
// Sem a tradução, uma cobrança PIX com o botão "review_and_pay" sai com
// name="review_and_pay" no nó, e o servidor recusa com o erro 405.

import (
	"os"
	"strconv"

	waBinary "github.com/polymorfa/hypermeow/binary"
)

// nativeFlowNames lista os botões cujo fluxo tem outro nome. Os demais nomes
// valem como o próprio fluxo.
var nativeFlowNames = map[string]string{
	"review_and_pay": "order_details",
	"review_order":   "order_status",
	"open_webview":   "message_with_link",
	"booking_status": "booking_confirmation",
}

// mixedButtons são os botões de resposta, de ação e de lista. O servidor recusa com o
// erro 405 o <native_flow> que leva o nome deles (confirmado em teste com o WhatsApp
// Business, 2026-11-09, com quick_reply e single_select) e aceita "mixed", que é o
// nome que o Baileys também usa nesses casos.
var mixedButtons = map[string]bool{
	"quick_reply":   true,
	"cta_url":       true,
	"cta_call":      true,
	"cta_copy":      true,
	"single_select": true,
}

// nativeFlowNameForButton devolve o nome do fluxo de um botão native_flow.
func nativeFlowNameForButton(button string) string {
	if flow, ok := nativeFlowNames[button]; ok {
		return flow
	}
	if mixedButtons[button] {
		return "mixed"
	}
	return button
}

// versionlessFlows são os fluxos de pedido e pagamento (isOrderNativeFlow, no módulo
// WAWebE2EProtoUtils do WhatsApp Web). Neles o <native_flow> leva só o name. Com
// v="9" o servidor recusa a mensagem com o erro 473 (confirmado em teste com o
// WhatsApp Business, 2026-11-09): o mesmo nó sem o atributo é aceito.
var versionlessFlows = map[string]bool{
	"order_details":  true,
	"order_status":   true,
	"payment_info":   true,
	"payment_status": true,
	"payment_method": true,
}

// Variantes do formato do nó <biz>, escolhidas por HYPERMEOW_BIZ_VARIANT.
// Servem para investigar recusas do servidor sem recompilar. Vazio ou
// desconhecido usa o formato padrão.
const (
	// bizVariantLegacy reproduz o comportamento anterior: nome do botão no nó.
	bizVariantLegacy = "legacy"
	// bizVariantNoQC é o formato padrão sem o filho <quality_control>.
	bizVariantNoQC = "no-qc"
	// bizVariantNoV tira o atributo v="9" de <native_flow> em todos os fluxos.
	bizVariantNoV = "no-v"
	// bizVariantV9 mantém v="9" em todos os fluxos, inclusive nos de pagamento
	// (reproduz o erro 473, com o nome do fluxo já traduzido).
	bizVariantV9 = "v9"
	// bizVariantWebInteractive é a segunda forma do cliente oficial:
	// <biz><interactive v="1" type="native_flow"><native_flow name/></interactive></biz>
	bizVariantWebInteractive = "web-interactive"
	// bizVariantWebName é a terceira forma do cliente oficial: <biz native_flow_name/>.
	bizVariantWebName = "web-name"
	// bizVariantWebPrivacy é a primeira forma do cliente oficial, sem filhos:
	// <biz host_storage actual_actors privacy_mode_ts native_flow_name/>.
	bizVariantWebPrivacy = "web-privacy"
)

// buildNativeFlowBizNodeFor monta o nó <biz> de uma mensagem native_flow.
// `button` é o nome do botão como foi enviado, e `flow` é o nome do fluxo já
// traduzido (ou "mixed", quando os botões têm fluxos diferentes).
func buildNativeFlowBizNodeFor(button, flow string, nowUnix int64) waBinary.Node {
	variant := os.Getenv("HYPERMEOW_BIZ_VARIANT")
	now := strconv.FormatInt(nowUnix, 10)

	if variant == bizVariantLegacy {
		flow = button
	}

	switch variant {
	case bizVariantWebInteractive:
		return waBinary.Node{
			Tag: "biz",
			Content: []waBinary.Node{
				{Tag: "interactive", Attrs: waBinary.Attrs{"type": "native_flow", "v": "1"}, Content: []waBinary.Node{
					{Tag: "native_flow", Attrs: waBinary.Attrs{"name": flow}},
				}},
			},
		}
	case bizVariantWebName:
		return waBinary.Node{Tag: "biz", Attrs: waBinary.Attrs{"native_flow_name": flow}}
	case bizVariantWebPrivacy:
		return waBinary.Node{
			Tag: "biz",
			Attrs: waBinary.Attrs{
				"host_storage":     "2",
				"actual_actors":    "2",
				"privacy_mode_ts":  now,
				"native_flow_name": flow,
			},
		}
	}

	omitVersion := versionlessFlows[flow]
	switch variant {
	case bizVariantNoV:
		omitVersion = true
	case bizVariantLegacy, bizVariantV9:
		omitVersion = false
	}
	flowAttrs := waBinary.Attrs{"name": flow, "v": "9"}
	if omitVersion {
		flowAttrs = waBinary.Attrs{"name": flow}
	}
	content := []waBinary.Node{
		{Tag: "interactive", Attrs: waBinary.Attrs{"type": "native_flow", "v": "1"}, Content: []waBinary.Node{
			{Tag: "native_flow", Attrs: flowAttrs},
		}},
	}
	if variant != bizVariantNoQC {
		content = append(content, waBinary.Node{Tag: "quality_control", Attrs: waBinary.Attrs{"source_type": "third_party"}})
	}
	return waBinary.Node{
		Tag: "biz",
		Attrs: waBinary.Attrs{
			"actual_actors":   "2",
			"host_storage":    "2",
			"privacy_mode_ts": now,
		},
		Content: content,
	}
}

// listBizType devolve o atributo type do nó <list> de uma ListMessage. O servidor aceita
// "product_list" (o valor que o Baileys envia) e recusa com o erro 405 o nome do tipo em
// minúsculas que o hypermeow mandava, como "single_select" (confirmado em teste com o WhatsApp
// Business, 2026-11-09; a mensagem chegou ao desktop e ao celular). HYPERMEOW_LIST_BIZ_TYPE
// troca o valor, para investigação.
func listBizType() string {
	if v := os.Getenv("HYPERMEOW_LIST_BIZ_TYPE"); v != "" {
		return v
	}
	return "product_list"
}
