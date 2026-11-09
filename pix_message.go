package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	whatsmeow "github.com/polymorfa/hypermeow"
	"github.com/polymorfa/hypermeow/proto/waE2E"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"
)

// O formato desta mensagem é o que o próprio cliente do WhatsApp monta e valida
// para cobranças PIX (módulos WAWebBizSendOrderAction, WAWebOrderDetails e
// WAWebE2EProtoUtils do WhatsApp Web, bundle 1053682356). Ver
// specs/029-botao-pix/research.md, seção R6.
//
// Três formas:
//
//	estática sem valor  -> botão "payment_info" (fluxo payment_info)
//	estática com valor  -> botão "review_and_pay" (fluxo order_details)
//	dinâmica            -> botão "review_and_pay" (fluxo order_details)
//
// O fluxo no nó <biz> é anexado pelo hypermeow a partir do nome do botão. Para
// "review_and_pay" o cliente espera "order_details"; sem o ajuste no hypermeow
// (R6) essas duas formas são descartadas pelo aparelho.

const (
	pixModeDynamic = "dynamic"
	pixModeStatic  = "static"

	pixButtonPaymentInfo  = "payment_info"
	pixButtonReviewAndPay = "review_and_pay"

	// Offset de 1000, o padrão do cliente oficial: value = centavos × 10.
	pixAmountOffset = 1000
	pixCentsToMilli = 10
)

// pixWrapInViewOnce define se a mensagem vai embrulhada em viewOnceMessage com
// messageContextInfo (receita usada pela lista). O cliente oficial envia sem o
// embrulho, e esse é o padrão. WUZAPI_PIX_VIEW_ONCE=true liga o embrulho, como
// variação de controle do spike S1 (specs/029-botao-pix/spike-s1.md).
func pixWrapInViewOnce() bool {
	return os.Getenv("WUZAPI_PIX_VIEW_ONCE") == "true"
}

var pixKeyTypes = map[string]bool{
	"CPF":   true,
	"CNPJ":  true,
	"EMAIL": true,
	"PHONE": true,
	"EVP":   true,
}

// pixRequest é o corpo de POST /chat/send/pix. O manager valida o formato da
// chave e do código; aqui só se confere presença e coerência entre os campos.
type pixRequest struct {
	Phone        string `json:"Phone"`
	Id           string `json:"Id,omitempty"`
	Body         string `json:"Body"`
	Footer       string `json:"Footer,omitempty"`
	Mode         string `json:"Mode"`
	AmountValue  int64  `json:"AmountValue"`
	Code         string `json:"Code,omitempty"`
	Key          string `json:"Key"`
	KeyType      string `json:"KeyType"`
	MerchantName string `json:"MerchantName"`
	ReferenceId  string `json:"ReferenceId"`
}

// validatePixRequest confere os campos obrigatórios e a coerência entre modo,
// valor e código. As mensagens de erro nunca incluem o código nem a chave.
func validatePixRequest(req pixRequest) error {
	if req.Body == "" {
		return errors.New("missing Body in Payload")
	}
	if req.Key == "" {
		return errors.New("missing Key in Payload")
	}
	if !pixKeyTypes[req.KeyType] {
		return errors.New("invalid KeyType in Payload")
	}
	if req.MerchantName == "" {
		return errors.New("missing MerchantName in Payload")
	}
	if req.ReferenceId == "" {
		return errors.New("missing ReferenceId in Payload")
	}
	if req.AmountValue < 0 {
		return errors.New("AmountValue cannot be negative")
	}
	switch req.Mode {
	case pixModeDynamic:
		if req.Code == "" {
			return errors.New("missing Code for dynamic Mode")
		}
		if req.AmountValue <= 0 {
			return errors.New("AmountValue must be greater than zero for dynamic Mode")
		}
	case pixModeStatic:
		if req.Code != "" {
			return errors.New("Code is not accepted for static Mode")
		}
	default:
		return errors.New("invalid Mode in Payload")
	}
	return nil
}

func pixAmount(milli int64) map[string]interface{} {
	return map[string]interface{}{"value": milli, "offset": pixAmountOffset}
}

// buildPixButton devolve o nome do botão e o buttonParamsJson da cobrança.
func buildPixButton(req pixRequest) (string, string, error) {
	totalMilli := req.AmountValue * pixCentsToMilli

	params := map[string]interface{}{
		"reference_id":          req.ReferenceId,
		"type":                  "physical-goods",
		"payment_configuration": "merchant_categorization_code",
		"currency":              "BRL",
		"total_amount":          pixAmount(totalMilli),
	}

	var settings map[string]interface{}
	if req.Mode == pixModeDynamic {
		settings = map[string]interface{}{
			"type": "pix_dynamic_code",
			"pix_dynamic_code": map[string]interface{}{
				"code":          req.Code,
				"merchant_name": req.MerchantName,
				"key":           req.Key,
				"key_type":      req.KeyType,
			},
		}
	} else {
		settings = map[string]interface{}{
			"type": "pix_static_code",
			"pix_static_code": map[string]interface{}{
				"merchant_name": req.MerchantName,
				"key":           req.Key,
				"key_type":      req.KeyType,
			},
		}
	}
	params["payment_settings"] = []interface{}{settings}

	button := pixButtonReviewAndPay
	if req.Mode == pixModeStatic && req.AmountValue == 0 {
		// "Enviar chave Pix": o cliente oficial manda o pedido zerado, com um
		// item vazio, e o botão payment_info.
		button = pixButtonPaymentInfo
		params["order"] = map[string]interface{}{
			"status": "pending",
			"items": []interface{}{
				map[string]interface{}{
					"quantity":      0,
					"retailer_id":   req.ReferenceId,
					"amount":        pixAmount(0),
					"name":          "",
					"product_id":    "",
					"isCustomItem":  false,
					"isQuantitySet": false,
				},
			},
			"subtotal": pixAmount(0),
			"tax":      nil,
			"shipping": nil,
			"discount": nil,
		}
	}

	encoded, err := json.Marshal(params)
	if err != nil {
		return "", "", err
	}
	return button, string(encoded), nil
}

// buildPixMessage monta a mensagem WhatsApp da cobrança PIX. É pura: não toca a
// rede nem a sessão, para ser testada sem cliente conectado.
func buildPixMessage(req pixRequest) (*waE2E.Message, error) {
	if err := validatePixRequest(req); err != nil {
		return nil, err
	}
	button, paramsJSON, err := buildPixButton(req)
	if err != nil {
		return nil, fmt.Errorf("could not build payment parameters: %w", err)
	}

	interactive := &waE2E.InteractiveMessage{
		Body: &waE2E.InteractiveMessage_Body{Text: proto.String(req.Body)},
		InteractiveMessage: &waE2E.InteractiveMessage_NativeFlowMessage_{
			NativeFlowMessage: &waE2E.InteractiveMessage_NativeFlowMessage{
				Buttons: []*waE2E.InteractiveMessage_NativeFlowMessage_NativeFlowButton{{
					Name:             proto.String(button),
					ButtonParamsJSON: proto.String(paramsJSON),
				}},
				MessageVersion: proto.Int32(nativeFlowMessageVersion),
			},
		},
	}
	if req.Footer != "" {
		interactive.Footer = &waE2E.InteractiveMessage_Footer{Text: proto.String(req.Footer)}
	}

	if pixWrapInViewOnce() {
		return &waE2E.Message{
			ViewOnceMessage: &waE2E.FutureProofMessage{
				Message: &waE2E.Message{
					MessageContextInfo: &waE2E.MessageContextInfo{
						DeviceListMetadata:        &waE2E.DeviceListMetadata{},
						DeviceListMetadataVersion: proto.Int32(2),
					},
					InteractiveMessage: interactive,
				},
			},
		}, nil
	}
	return &waE2E.Message{InteractiveMessage: interactive}, nil
}

// SendPix envia uma cobrança PIX (POST /chat/send/pix).
//
// A validação do corpo vem antes da checagem de sessão, para a recusa de um
// corpo inválido não depender de haver cliente conectado. Nenhum campo do corpo
// é registrado em log: o código e a chave PIX são dados financeiros.
func (s *server) SendPix() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		txtid := r.Context().Value("userinfo").(Values).Get("Id")

		var t pixRequest
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not decode Payload"))
			return
		}
		if t.Phone == "" {
			s.Respond(w, r, http.StatusBadRequest, errors.New("missing Phone in Payload"))
			return
		}
		if err := validatePixRequest(t); err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}
		recipient, ok := parseJID(t.Phone)
		if !ok {
			s.Respond(w, r, http.StatusBadRequest, errors.New("could not parse Phone"))
			return
		}
		msg, err := buildPixMessage(t)
		if err != nil {
			s.Respond(w, r, http.StatusBadRequest, err)
			return
		}

		client := clientManager.GetWhatsmeowClient(txtid)
		if client == nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New("no session"))
			return
		}

		msgid := t.Id
		if msgid == "" {
			msgid = client.GenerateMessageID()
		}

		// Sem AdditionalNodes: o hypermeow anexa o nó <biz> do native_flow.
		resp, err := client.SendMessage(
			context.Background(),
			recipient,
			msg,
			whatsmeow.SendRequestExtra{ID: msgid},
		)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, errors.New(fmt.Sprintf("error sending message: %v", err)))
			return
		}

		log.Info().Str("id", msgid).Msg("Message pix sent")
		response := map[string]interface{}{
			"Details":   "Sent",
			"Timestamp": resp.Timestamp.Unix(),
			"Id":        msgid,
		}
		responseJson, err := json.Marshal(response)
		if err != nil {
			s.Respond(w, r, http.StatusInternalServerError, err)
		} else {
			s.Respond(w, r, http.StatusOK, string(responseJson))
		}
	}
}
