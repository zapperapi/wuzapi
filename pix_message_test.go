package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Vetores de teste: nenhuma chave ou código reais.
const (
	testPixCode = "00020101021226500014br.gov.bcb.pix2528pix.example.com/qr/v2/abc1235204000053039865802BR5910Loja Teste6009SAO PAULO62070503***6304F0BB"
	testPixKey  = "39580525000189"
)

func dynamicPixRequest() pixRequest {
	return pixRequest{
		Phone:        "5511999999999",
		Body:         "Sua fatura de novembro",
		Footer:       "Vence em 10/11",
		Mode:         "dynamic",
		AmountValue:  15050,
		Code:         testPixCode,
		Key:          testPixKey,
		KeyType:      "CNPJ",
		MerchantName: "Loja Exemplo",
		ReferenceId:  "fatura-123.k3j9x0a7qp",
	}
}

func staticPixRequest(amount int64) pixRequest {
	return pixRequest{
		Phone:        "5511999999999",
		Body:         "Pagamento via PIX",
		Mode:         "static",
		AmountValue:  amount,
		Key:          "pagamentos@loja.com.br",
		KeyType:      "EMAIL",
		MerchantName: "Loja Exemplo",
		ReferenceId:  "fatura-123.k3j9x0a7qp",
	}
}

// pixButton extrai o único botão native_flow da mensagem construída e decodifica
// o buttonParamsJson, para comparar o conteúdo e não a ordem das chaves.
func pixButton(t *testing.T, req pixRequest) (name string, params map[string]interface{}, version int32) {
	t.Helper()
	msg, err := buildPixMessage(req)
	if err != nil {
		t.Fatalf("buildPixMessage: %v", err)
	}
	inner := msg
	if msg.ViewOnceMessage != nil {
		inner = msg.ViewOnceMessage.Message
	}
	im := inner.GetInteractiveMessage()
	if im == nil {
		t.Fatalf("mensagem sem InteractiveMessage")
	}
	nf := im.GetNativeFlowMessage()
	if nf == nil {
		t.Fatalf("InteractiveMessage sem NativeFlowMessage")
	}
	buttons := nf.GetButtons()
	if len(buttons) != 1 {
		t.Fatalf("esperado 1 botão, veio %d", len(buttons))
	}
	if err := json.Unmarshal([]byte(buttons[0].GetButtonParamsJSON()), &params); err != nil {
		t.Fatalf("buttonParamsJson inválido: %v", err)
	}
	return buttons[0].GetName(), params, nf.GetMessageVersion()
}

func pixObject(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	m, ok := v.(map[string]interface{})
	if !ok {
		t.Fatalf("esperado objeto, veio %T (%v)", v, v)
	}
	return m
}

func TestBuildPixMessage_StaticWithoutAmount(t *testing.T) {
	name, params, version := pixButton(t, staticPixRequest(0))

	if name != "payment_info" {
		t.Errorf("botão = %q, esperado payment_info", name)
	}
	if version != 1 {
		t.Errorf("MessageVersion = %d, esperado 1", version)
	}
	if params["currency"] != "BRL" || params["type"] != "physical-goods" ||
		params["payment_configuration"] != "merchant_categorization_code" ||
		params["reference_id"] != "fatura-123.k3j9x0a7qp" {
		t.Errorf("campos comuns incorretos: %v", params)
	}
	total := pixObject(t, params["total_amount"])
	if total["value"] != float64(0) || total["offset"] != float64(1000) {
		t.Errorf("total_amount = %v, esperado {0, 1000}", total)
	}
	settings := params["payment_settings"].([]interface{})
	if len(settings) != 1 {
		t.Fatalf("payment_settings com %d itens", len(settings))
	}
	first := pixObject(t, settings[0])
	if first["type"] != "pix_static_code" {
		t.Errorf("type = %v, esperado pix_static_code", first["type"])
	}
	code := pixObject(t, first["pix_static_code"])
	if code["merchant_name"] != "Loja Exemplo" || code["key"] != "pagamentos@loja.com.br" || code["key_type"] != "EMAIL" {
		t.Errorf("pix_static_code incorreto: %v", code)
	}
	order := pixObject(t, params["order"])
	if order["status"] != "pending" {
		t.Errorf("order.status = %v", order["status"])
	}
	items := order["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("order.items com %d itens, esperado 1", len(items))
	}
	item := pixObject(t, items[0])
	if item["quantity"] != float64(0) || item["retailer_id"] != "fatura-123.k3j9x0a7qp" {
		t.Errorf("item incorreto: %v", item)
	}
	if v, present := order["tax"]; !present || v != nil {
		t.Errorf("order.tax deve existir e ser null, veio %v (presente=%v)", v, present)
	}
}

func TestBuildPixMessage_StaticWithAmount(t *testing.T) {
	name, params, version := pixButton(t, staticPixRequest(15050))

	if name != "review_and_pay" {
		t.Errorf("botão = %q, esperado review_and_pay", name)
	}
	if version != 1 {
		t.Errorf("MessageVersion = %d, esperado 1", version)
	}
	total := pixObject(t, params["total_amount"])
	if total["value"] != float64(150500) || total["offset"] != float64(1000) {
		t.Errorf("total_amount = %v, esperado {150500, 1000}", total)
	}
	if _, present := params["order"]; present {
		t.Errorf("estática com valor não leva order, veio %v", params["order"])
	}
	first := pixObject(t, params["payment_settings"].([]interface{})[0])
	if first["type"] != "pix_static_code" {
		t.Errorf("type = %v, esperado pix_static_code", first["type"])
	}
}

func TestBuildPixMessage_Dynamic(t *testing.T) {
	name, params, version := pixButton(t, dynamicPixRequest())

	if name != "review_and_pay" {
		t.Errorf("botão = %q, esperado review_and_pay", name)
	}
	if version != 1 {
		t.Errorf("MessageVersion = %d, esperado 1", version)
	}
	total := pixObject(t, params["total_amount"])
	if total["value"] != float64(150500) || total["offset"] != float64(1000) {
		t.Errorf("total_amount = %v, esperado {150500, 1000}", total)
	}
	first := pixObject(t, params["payment_settings"].([]interface{})[0])
	if first["type"] != "pix_dynamic_code" {
		t.Fatalf("type = %v, esperado pix_dynamic_code", first["type"])
	}
	dyn := pixObject(t, first["pix_dynamic_code"])
	if dyn["code"] != testPixCode || dyn["merchant_name"] != "Loja Exemplo" ||
		dyn["key"] != testPixKey || dyn["key_type"] != "CNPJ" {
		t.Errorf("pix_dynamic_code incorreto: %v", dyn)
	}
	if _, present := params["order"]; present {
		t.Errorf("dinâmica não leva order")
	}
}

func TestBuildPixMessage_BodyAndFooter(t *testing.T) {
	msg, err := buildPixMessage(dynamicPixRequest())
	if err != nil {
		t.Fatal(err)
	}
	inner := msg
	if msg.ViewOnceMessage != nil {
		inner = msg.ViewOnceMessage.Message
	}
	im := inner.GetInteractiveMessage()
	if im.GetBody().GetText() != "Sua fatura de novembro" {
		t.Errorf("body = %q", im.GetBody().GetText())
	}
	if im.GetFooter().GetText() != "Vence em 10/11" {
		t.Errorf("footer = %q", im.GetFooter().GetText())
	}

	noFooter := dynamicPixRequest()
	noFooter.Footer = ""
	msg, _ = buildPixMessage(noFooter)
	inner = msg
	if msg.ViewOnceMessage != nil {
		inner = msg.ViewOnceMessage.Message
	}
	if inner.GetInteractiveMessage().GetFooter() != nil {
		t.Errorf("sem rodapé informado, Footer deve ficar ausente")
	}
}

func TestBuildPixMessage_Validation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*pixRequest)
	}{
		{"modo inválido", func(r *pixRequest) { r.Mode = "outro" }},
		{"modo vazio", func(r *pixRequest) { r.Mode = "" }},
		{"dinâmica sem Code", func(r *pixRequest) { r.Code = "" }},
		{"dinâmica sem valor", func(r *pixRequest) { r.AmountValue = 0 }},
		{"dinâmica com valor negativo", func(r *pixRequest) { r.AmountValue = -1 }},
		{"estática com Code", func(r *pixRequest) {
			*r = staticPixRequest(0)
			r.Code = testPixCode
		}},
		{"estática com valor negativo", func(r *pixRequest) {
			*r = staticPixRequest(0)
			r.AmountValue = -5
		}},
		{"sem Body", func(r *pixRequest) { r.Body = "" }},
		{"sem Key", func(r *pixRequest) { r.Key = "" }},
		{"KeyType inválido", func(r *pixRequest) { r.KeyType = "XYZ" }},
		{"sem MerchantName", func(r *pixRequest) { r.MerchantName = "" }},
		{"sem ReferenceId", func(r *pixRequest) { r.ReferenceId = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := dynamicPixRequest()
			tc.mutate(&req)
			if _, err := buildPixMessage(req); err == nil {
				t.Errorf("esperava erro de validação")
			}
		})
	}
}

func TestBuildPixMessage_ErrorDoesNotLeakSecrets(t *testing.T) {
	req := dynamicPixRequest()
	req.KeyType = "XYZ"
	_, err := buildPixMessage(req)
	if err == nil {
		t.Fatal("esperava erro")
	}
	for _, secret := range []string{testPixCode, testPixKey, "br.gov.bcb.pix"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("a mensagem de erro contém dado sensível: %q", err.Error())
		}
	}
}

// pixEndpoint envia o corpo ao roteador real, com um usuário semeado.
func pixEndpoint(t *testing.T, s *server, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/chat/send/pix", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("token", token)
	}
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	return rr
}

func TestSendPixEndpoint(t *testing.T) {
	s := makeTestServer(t)
	const token = "tok-pix"
	if _, err := s.db.Exec(
		`INSERT INTO users (id, name, token, connected) VALUES ($1,$2,$3,$4)`,
		"u-pix", "tester", token, 0); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	validBody, _ := json.Marshal(dynamicPixRequest())

	t.Run("sem token responde 401", func(t *testing.T) {
		rr := pixEndpoint(t, s, "", string(validBody))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, esperado 401: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("JSON inválido responde 400", func(t *testing.T) {
		rr := pixEndpoint(t, s, token, "{nao e json")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, esperado 400: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("sem Phone responde 400", func(t *testing.T) {
		req := dynamicPixRequest()
		req.Phone = ""
		b, _ := json.Marshal(req)
		rr := pixEndpoint(t, s, token, string(b))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, esperado 400: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("Mode inválido responde 400", func(t *testing.T) {
		req := dynamicPixRequest()
		req.Mode = "outro"
		b, _ := json.Marshal(req)
		rr := pixEndpoint(t, s, token, string(b))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, esperado 400: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("dinâmica sem Code responde 400", func(t *testing.T) {
		req := dynamicPixRequest()
		req.Code = ""
		b, _ := json.Marshal(req)
		rr := pixEndpoint(t, s, token, string(b))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, esperado 400: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("estática com Code responde 400", func(t *testing.T) {
		req := staticPixRequest(0)
		req.Code = testPixCode
		b, _ := json.Marshal(req)
		rr := pixEndpoint(t, s, token, string(b))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, esperado 400: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("a resposta de recusa não contém código nem chave", func(t *testing.T) {
		req := dynamicPixRequest()
		req.KeyType = "XYZ"
		b, _ := json.Marshal(req)
		rr := pixEndpoint(t, s, token, string(b))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, esperado 400", rr.Code)
		}
		for _, secret := range []string{testPixCode, testPixKey} {
			if strings.Contains(rr.Body.String(), secret) {
				t.Errorf("a resposta contém dado sensível")
			}
		}
	})

	t.Run("corpo válido sem sessão responde 500 no session", func(t *testing.T) {
		rr := pixEndpoint(t, s, token, string(validBody))
		if rr.Code == http.StatusNotFound {
			t.Fatalf("rota /chat/send/pix não registrada (404)")
		}
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "no session") {
			t.Errorf("esperado 500 \"no session\"; veio %d: %s", rr.Code, rr.Body.String())
		}
	})
}
