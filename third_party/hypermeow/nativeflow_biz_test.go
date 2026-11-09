package whatsmeow

import (
	"testing"

	waBinary "github.com/polymorfa/hypermeow/binary"
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"google.golang.org/protobuf/proto"
)

func nativeFlowMessage(buttonNames ...string) *waE2E.Message {
	buttons := make([]*waE2E.InteractiveMessage_NativeFlowMessage_NativeFlowButton, len(buttonNames))
	for i, name := range buttonNames {
		buttons[i] = &waE2E.InteractiveMessage_NativeFlowMessage_NativeFlowButton{
			Name:             proto.String(name),
			ButtonParamsJSON: proto.String("{}"),
		}
	}
	return &waE2E.Message{InteractiveMessage: &waE2E.InteractiveMessage{
		Body: &waE2E.InteractiveMessage_Body{Text: proto.String("corpo")},
		InteractiveMessage: &waE2E.InteractiveMessage_NativeFlowMessage_{
			NativeFlowMessage: &waE2E.InteractiveMessage_NativeFlowMessage{
				Buttons:        buttons,
				MessageVersion: proto.Int32(1),
			},
		},
	}}
}

// flowNameOf lê o nome do fluxo de um nó <biz>, em qualquer das formas.
func flowNameOf(t *testing.T, node waBinary.Node) string {
	t.Helper()
	if node.Tag != "biz" {
		t.Fatalf("tag = %q, esperado biz", node.Tag)
	}
	if name, ok := node.Attrs["native_flow_name"].(string); ok {
		return name
	}
	children, _ := node.Content.([]waBinary.Node)
	for _, child := range children {
		if child.Tag != "interactive" {
			continue
		}
		inner, _ := child.Content.([]waBinary.Node)
		for _, flow := range inner {
			if flow.Tag == "native_flow" {
				return flow.Attrs["name"].(string)
			}
		}
	}
	t.Fatalf("nó <biz> sem nome de fluxo: %+v", node)
	return ""
}

func childTags(node waBinary.Node) []string {
	children, _ := node.Content.([]waBinary.Node)
	tags := make([]string, len(children))
	for i, child := range children {
		tags[i] = child.Tag
	}
	return tags
}

func TestNativeFlowNameForButton(t *testing.T) {
	cases := map[string]string{
		"review_and_pay":    "order_details",
		"review_order":      "order_status",
		"open_webview":      "message_with_link",
		"booking_status":    "booking_confirmation",
		"payment_info":      "payment_info",
		"quick_reply":       "mixed",
		"cta_call":          "mixed",
		"cta_copy":          "mixed",
		"single_select":     "mixed",
		"cta_url":           "mixed",
		"galaxy_message":    "galaxy_message",
		"address_message":   "address_message",
		"nome_desconhecido": "nome_desconhecido",
	}
	for button, want := range cases {
		if got := nativeFlowNameForButton(button); got != want {
			t.Errorf("nativeFlowNameForButton(%q) = %q, esperado %q", button, got, want)
		}
	}
}

func TestBuildNativeFlowBizNode_DefaultTranslatesButtonName(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "")
	node := buildNativeFlowBizNode(nativeFlowMessage("review_and_pay"), 1762600000)

	if got := flowNameOf(t, node); got != "order_details" {
		t.Errorf("fluxo = %q, esperado order_details", got)
	}
	if node.Attrs["privacy_mode_ts"] != "1762600000" || node.Attrs["actual_actors"] != "2" || node.Attrs["host_storage"] != "2" {
		t.Errorf("atributos do <biz> mudaram: %v", node.Attrs)
	}
	tags := childTags(node)
	if len(tags) != 2 || tags[0] != "interactive" || tags[1] != "quality_control" {
		t.Errorf("filhos = %v, esperado [interactive quality_control]", tags)
	}
	interactive := node.Content.([]waBinary.Node)[0]
	flow := interactive.Content.([]waBinary.Node)[0]
	if interactive.Attrs["v"] != "1" || interactive.Attrs["type"] != "native_flow" {
		t.Errorf("interactive mudou: %v", interactive.Attrs)
	}
	if _, hasV := flow.Attrs["v"]; hasV {
		t.Errorf("fluxo de pagamento não leva v no native_flow, veio %v", flow.Attrs)
	}
}

func TestBuildNativeFlowBizNode_KeepsVersionOutsidePaymentFlows(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "")
	for _, name := range []string{"quick_reply", "cta_url", "cta_copy", "single_select", "galaxy_message"} {
		node := buildNativeFlowBizNode(nativeFlowMessage(name), 1)
		interactive := node.Content.([]waBinary.Node)[0]
		flow := interactive.Content.([]waBinary.Node)[0]
		if flow.Attrs["v"] != "9" {
			t.Errorf("botão %q: native_flow deveria manter v=9 (comportamento anterior), veio %v", name, flow.Attrs)
		}
	}
}

func TestBuildNativeFlowBizNode_PaymentFlowsHaveNoVersion(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "")
	for _, name := range []string{"review_and_pay", "payment_info", "review_order", "payment_status", "payment_method"} {
		node := buildNativeFlowBizNode(nativeFlowMessage(name), 1)
		interactive := node.Content.([]waBinary.Node)[0]
		flow := interactive.Content.([]waBinary.Node)[0]
		if _, hasV := flow.Attrs["v"]; hasV {
			t.Errorf("botão %q: native_flow não deve ter v, veio %v", name, flow.Attrs)
		}
	}
}

func TestBuildNativeFlowBizNode_V9VariantKeepsVersionOnPayments(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "v9")
	node := buildNativeFlowBizNode(nativeFlowMessage("payment_info"), 1)
	flow := node.Content.([]waBinary.Node)[0].Content.([]waBinary.Node)[0]
	if flow.Attrs["v"] != "9" || flow.Attrs["name"] != "payment_info" {
		t.Errorf("v9 reproduz o formato que o servidor recusa: %v", flow.Attrs)
	}
}

func TestBuildNativeFlowBizNode_KeepsOtherButtonNames(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "")
	for _, name := range []string{"payment_info", "galaxy_message", "address_message", "cta_catalog"} {
		if got := flowNameOf(t, buildNativeFlowBizNode(nativeFlowMessage(name), 1)); got != name {
			t.Errorf("botão %q: fluxo = %q, esperado %q", name, got, name)
		}
	}
}

func TestBuildNativeFlowBizNode_MixedWhenButtonsDiffer(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "")
	got := flowNameOf(t, buildNativeFlowBizNode(nativeFlowMessage("quick_reply", "cta_url"), 1))
	if got != "mixed" {
		t.Errorf("fluxo = %q, esperado mixed", got)
	}
}

func TestBuildNativeFlowBizNode_SameButtonsFlow(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "")
	got := flowNameOf(t, buildNativeFlowBizNode(nativeFlowMessage("quick_reply", "quick_reply"), 1))
	if got != "mixed" {
		t.Errorf("botões de resposta usam o fluxo mixed, veio %q", got)
	}
	got = flowNameOf(t, buildNativeFlowBizNode(nativeFlowMessage("galaxy_message", "galaxy_message"), 1))
	if got != "galaxy_message" {
		t.Errorf("fluxo = %q, esperado galaxy_message", got)
	}
}

func TestBuildNativeFlowBizNode_NoButtonsIsMixed(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "")
	if got := flowNameOf(t, buildNativeFlowBizNode(nativeFlowMessage(), 1)); got != "mixed" {
		t.Errorf("fluxo = %q, esperado mixed", got)
	}
}

func TestBuildNativeFlowBizNode_UnwrapsViewOnce(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "")
	wrapped := &waE2E.Message{ViewOnceMessage: &waE2E.FutureProofMessage{Message: nativeFlowMessage("review_and_pay")}}
	if got := flowNameOf(t, buildNativeFlowBizNode(wrapped, 1)); got != "order_details" {
		t.Errorf("fluxo = %q, esperado order_details", got)
	}
}

func TestBuildNativeFlowBizNode_LegacyKeepsButtonName(t *testing.T) {
	t.Setenv("HYPERMEOW_BIZ_VARIANT", "legacy")
	node := buildNativeFlowBizNode(nativeFlowMessage("review_and_pay"), 1762600000)

	if got := flowNameOf(t, node); got != "review_and_pay" {
		t.Errorf("legacy: fluxo = %q, esperado review_and_pay (comportamento antigo)", got)
	}
	tags := childTags(node)
	if len(tags) != 2 || tags[1] != "quality_control" {
		t.Errorf("legacy mantém o formato padrão; filhos = %v", tags)
	}
	flow := node.Content.([]waBinary.Node)[0].Content.([]waBinary.Node)[0]
	if flow.Attrs["v"] != "9" {
		t.Errorf("legacy mantém v=9, veio %v", flow.Attrs)
	}
}

func TestBuildNativeFlowBizNode_Variants(t *testing.T) {
	msg := nativeFlowMessage("review_and_pay")

	t.Run("no-qc", func(t *testing.T) {
		t.Setenv("HYPERMEOW_BIZ_VARIANT", "no-qc")
		node := buildNativeFlowBizNode(msg, 7)
		if tags := childTags(node); len(tags) != 1 || tags[0] != "interactive" {
			t.Errorf("filhos = %v, esperado [interactive]", tags)
		}
		if flowNameOf(t, node) != "order_details" {
			t.Errorf("fluxo errado")
		}
		if node.Attrs["privacy_mode_ts"] != "7" {
			t.Errorf("no-qc mantém os atributos padrão: %v", node.Attrs)
		}
	})

	t.Run("no-v", func(t *testing.T) {
		t.Setenv("HYPERMEOW_BIZ_VARIANT", "no-v")
		node := buildNativeFlowBizNode(msg, 7)
		interactive := node.Content.([]waBinary.Node)[0]
		flow := interactive.Content.([]waBinary.Node)[0]
		if _, hasV := flow.Attrs["v"]; hasV {
			t.Errorf("native_flow não deve ter v, veio %v", flow.Attrs)
		}
		if flow.Attrs["name"] != "order_details" || node.Attrs["privacy_mode_ts"] != "7" {
			t.Errorf("no-v mantém o resto do formato padrão: %v / %v", node.Attrs, flow.Attrs)
		}
		if tags := childTags(node); len(tags) != 2 || tags[1] != "quality_control" {
			t.Errorf("no-v mantém o quality_control; filhos = %v", tags)
		}
	})

	t.Run("web-interactive", func(t *testing.T) {
		t.Setenv("HYPERMEOW_BIZ_VARIANT", "web-interactive")
		node := buildNativeFlowBizNode(msg, 7)
		if len(node.Attrs) != 0 {
			t.Errorf("<biz> sem atributos, veio %v", node.Attrs)
		}
		interactive := node.Content.([]waBinary.Node)[0]
		flow := interactive.Content.([]waBinary.Node)[0]
		if interactive.Attrs["v"] != "1" || interactive.Attrs["type"] != "native_flow" {
			t.Errorf("interactive = %v", interactive.Attrs)
		}
		if _, hasV := flow.Attrs["v"]; hasV || flow.Attrs["name"] != "order_details" {
			t.Errorf("native_flow deve ter só name, veio %v", flow.Attrs)
		}
	})

	t.Run("web-name", func(t *testing.T) {
		t.Setenv("HYPERMEOW_BIZ_VARIANT", "web-name")
		node := buildNativeFlowBizNode(msg, 7)
		if len(node.Attrs) != 1 || node.Attrs["native_flow_name"] != "order_details" {
			t.Errorf("atributos = %v, esperado só native_flow_name", node.Attrs)
		}
		if node.Content != nil {
			t.Errorf("sem filhos, veio %v", node.Content)
		}
	})

	t.Run("web-privacy", func(t *testing.T) {
		t.Setenv("HYPERMEOW_BIZ_VARIANT", "web-privacy")
		node := buildNativeFlowBizNode(msg, 7)
		want := waBinary.Attrs{
			"host_storage":     "2",
			"actual_actors":    "2",
			"privacy_mode_ts":  "7",
			"native_flow_name": "order_details",
		}
		for key, value := range want {
			if node.Attrs[key] != value {
				t.Errorf("atributo %s = %v, esperado %v", key, node.Attrs[key], value)
			}
		}
		if node.Content != nil {
			t.Errorf("sem filhos, veio %v", node.Content)
		}
	})

	t.Run("variante desconhecida usa o padrão", func(t *testing.T) {
		t.Setenv("HYPERMEOW_BIZ_VARIANT", "qualquer-coisa")
		node := buildNativeFlowBizNode(msg, 7)
		if flowNameOf(t, node) != "order_details" || len(childTags(node)) != 2 {
			t.Errorf("deveria cair no formato padrão: %+v", node)
		}
	})
}

func TestGetButtonAttributes_ListUsesProductList(t *testing.T) {
	t.Setenv("HYPERMEOW_LIST_BIZ_TYPE", "")
	msg := &waE2E.Message{ListMessage: &waE2E.ListMessage{
		ListType: waE2E.ListMessage_SINGLE_SELECT.Enum(),
	}}
	attrs := getButtonAttributes(msg)
	if attrs["v"] != "2" || attrs["type"] != "product_list" {
		t.Errorf("nó <list> = %v, esperado v=2 type=product_list", attrs)
	}
}

func TestGetButtonAttributes_ListTypeOverride(t *testing.T) {
	t.Setenv("HYPERMEOW_LIST_BIZ_TYPE", "single_select")
	msg := &waE2E.Message{ListMessage: &waE2E.ListMessage{
		ListType: waE2E.ListMessage_SINGLE_SELECT.Enum(),
	}}
	if got := getButtonAttributes(msg)["type"]; got != "single_select" {
		t.Errorf("type = %v, esperado single_select (override)", got)
	}
}

func TestGetButtonAttributes_ListUnwrapsViewOnce(t *testing.T) {
	t.Setenv("HYPERMEOW_LIST_BIZ_TYPE", "")
	msg := &waE2E.Message{ViewOnceMessage: &waE2E.FutureProofMessage{Message: &waE2E.Message{
		ListMessage: &waE2E.ListMessage{ListType: waE2E.ListMessage_SINGLE_SELECT.Enum()},
	}}}
	if got := getButtonAttributes(msg)["type"]; got != "product_list" {
		t.Errorf("type = %v, esperado product_list", got)
	}
}
