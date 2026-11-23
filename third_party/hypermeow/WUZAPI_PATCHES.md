# Patches do wuzapi sobre o hypermeow

Esta pasta é uma cópia de `github.com/polymorfa/hypermeow`, versão
`v0.0.0-20260811214557-f9db181f1dfa`, a mesma que o wuzapi usava antes do
`replace` em `go.mod`. O fork é de terceiros. Cada alteração fica aqui, para
uma atualização futura saber o que reaplicar ou descartar.

## 1. Nome do fluxo no nó `<biz>` de mensagens native_flow

- **Arquivos:** `nativeflow_biz.go` (novo), `nativeflow_biz_test.go` (novo) e
  `send.go` (`buildNativeFlowBizNode` passa a chamar `buildNativeFlowBizNodeFor`).
- **Problema:** o nó `<biz>` levava o nome do botão. O cliente oficial leva o nome do
  **fluxo** que deriva do botão (`getNativeFlowNameByButtonName`, módulo
  `WAWebBizTemplateAndInteractiveMessagesUtils` do WhatsApp Web 2.3000.1053682356).
  Para `review_and_pay` o nó saía `review_and_pay` em vez de `order_details`, e o servidor
  recusava a cobrança PIX com o erro 405.
- **Mudança:** tabela `nativeFlowNames` com as quatro exceções (`review_and_pay`,
  `review_order`, `open_webview`, `booking_status`). Os outros nomes seguem iguais.

## 2. Sem `v="9"` nos fluxos de pedido e pagamento

- **Arquivos:** `nativeflow_biz.go` (`versionlessFlows`) e os testes.
- **Problema:** o `<native_flow>` saía com `v="9"`. Com esse atributo, o servidor do WhatsApp
  recusava a cobrança PIX com o erro 473, mesmo com o nome do fluxo certo.
- **Evidência** (teste local com WhatsApp Business, 2026-11-09, mesma mensagem, só o nó mudou):
  `v="9"` → 473 (padrão e `no-qc`); sem `v` → aceito (`no-v`, `web-interactive`);
  sem `<interactive>` → aceito (`web-name`, `web-privacy`).
- **Mudança:** nos fluxos `order_details`, `order_status`, `payment_info`, `payment_status` e
  `payment_method`, o `<native_flow>` leva só `name`. Os outros fluxos (botões, lista etc.)
  mantêm `v="9"`, para não mudar o que já funciona.

## 3. Nome do fluxo `mixed` para botões de resposta, ação e lista

- **Arquivo:** `nativeflow_biz.go` (`mixedButtons`).
- **Problema:** para `quick_reply`, `cta_url`, `cta_call`, `cta_copy` e `single_select`, o nó levava
  o nome do botão, e o servidor recusava com o erro 405. O nome `mixed` é aceito (o Baileys
  também o usa nesses casos).
- **Mudança:** esses cinco botões usam `mixed`, com `v="9"` mantido (sem `v` o servidor recusa com 473).

## 4. Nó `<list>` com `type="product_list"`

- **Arquivos:** `nativeflow_biz.go` (`listBizType`) e `send.go` (`getButtonAttributes`).
- **Problema:** para `ListMessage` o nó saía `<list v="2" type="single_select">`, e o servidor recusava
  com o erro 405. Foi o que levou o wuzapi a enviar listas por native flow, que não chega ao aparelho.
- **Evidência** (teste local, 2026-11-09): `single_select` → 405; `product_list` → aceito, e a
  lista chegou ao desktop e ao celular.
- **Mudança:** `type="product_list"` por padrão. O teste `messaging_test.go`
  (`TestListBusinessMetadataUnwrapsViewOnceV2Extension`) foi atualizado para o novo valor.
  `HYPERMEOW_LIST_BIZ_TYPE` troca o valor, para investigação.

## 5. Variantes do formato do nó (investigação)

`HYPERMEOW_BIZ_VARIANT` escolhe o formato do `<biz>` sem recompilar. Vazio usa o padrão.

| Valor | Formato |
|---|---|
| (vazio) | Padrão: atributos fixos, `<interactive v="1">` com `<native_flow name v="9">` e `<quality_control>`, com o nome do fluxo traduzido |
| `legacy` | Comportamento anterior ao patch: nome do botão no nó |
| `no-qc` | Padrão sem `<quality_control>` |
| `no-v` | Tira o `v="9"` de `<native_flow>` em todos os fluxos |
| `v9` | Mantém `v="9"` também nos fluxos de pagamento (reproduz o 473) |
| `web-interactive` | `<biz><interactive v="1" type="native_flow"><native_flow name/></interactive></biz>` |
| `web-name` | `<biz native_flow_name/>` |
| `web-privacy` | `<biz host_storage actual_actors privacy_mode_ts native_flow_name/>` |

As três últimas são as formas do cliente oficial (`WAWebSendMsgCreateFanoutStanza`).
Quando a investigação terminar, manter só o formato que o servidor aceita e remover o resto.

## 6. Recado (about) por `<text_status>` no `GetUserInfo`

- **Arquivos:** `user.go` (`GetUserInfo`, `parseUSyncAbout`) e `usync_about_test.go` (novo).
- **Problema:** o `GetUserInfo` lia o recado só do protocolo usync `<status>`. O WhatsApp Web
  2.3000.1055901559 removeu esse protocolo (`WAWebUsyncStatus`, `WAWebGetAboutQueryJob` e
  `include_about_status` não existem mais) e lê o recado de `<text_status text="...">`
  (`WAWebUsyncTextStatus`).
- **Mudança:** a consulta pede `<status>` e `<text_status>`. O valor de `<status>` tem prioridade;
  sem ele, vale o atributo `text` de `<text_status>`. Um `<text_status>` com `<error>` dá recado vazio.
- **Não verificado:** a resposta do servidor a `<text_status>` não foi testada com uma conta real.

## 7. Recibo de erro `integrity-drop`

- **Arquivos:** `receipt.go` (`parseReceiptErrorType`), `types/presence.go` (`ReceiptTypeError`),
  `types/events/events.go` (`Receipt.ErrorType`, `ReceiptErrorIntegrityDrop`, `IsIntegrityDrop`)
  e `usync_about_test.go`.
- **Problema:** o servidor avisa que descartou uma mensagem com
  `<receipt type="error"><error type="integrity-drop"/></receipt>`. O hypermeow não lia o nó
  `<error>`, e o wuzapi descartava o recibo. O cliente oficial marca a mensagem como falha
  (`WAWebHandleMsgReceiptParser`, WhatsApp Web 2.3000.1055901559).
- **Mudança:** `events.Receipt` leva `ErrorType` nos recibos `type="error"`. O wuzapi (`wmiau.go`)
  envia o webhook `ReadReceipt` com `state: "Failed"` e `reason: "integrity-drop"`.

## 10. Protobuf do WhatsApp Web 2.3000.1055901559

- **Arquivos:** 18 `.proto` em `proto/`, os `.pb.go` correspondentes e `proto/protomerge.py` (novo).
- **Problema:** os `.proto` do fork eram da revisão `1044834443`. Faltavam mensagens e campos que o
  cliente oficial já usa.
- **Mudança:** `protomerge.py` lê os módulos `*.pb.js` do bundle (cellar) sem executar o código e
  mescla o resultado nos `.proto`. Os nomes que o fork já adaptou (`stanzaID`, `JID`, tipos de
  `Message` no nível de cima) ficam iguais. Entraram 94 mensagens, 22 enums, 384 campos e 221 valores de enum.
- **Removido ou alterado pelo bundle:**
  - `Message.newsletterAdminProfileMessageV2` (campo 117) saiu.
  - `ChatSolidColorWallpaper`: `colorLight` e `colorDark` (`string`) passaram a `backgroundLightArgb`
    e `backgroundDarkArgb` (`fixed32`).
  - `XmatMessengerMessageReminderSet` e `...Triggered`: `scheduledTime` passou de `int64` a `string`.
  - `WAWebLabyrinthWaWasm`: as saídas (`*Output`) usam o `oneof result` com `success` e `error`.
- **Sem módulo no bundle (intocados):** `waArmadilloICDC`, `waBotMetadata`, `waCommonParameterised`,
  `waConsumerApplicationParameterised`, `waMultiDevice`, `waLidMigrationSyncPayload`, `waE2EGuest`
  e `waWinUIApi`. `waReporting` é mantido à mão: recebe acréscimos, nunca remoções.
- **Como repetir** (a partir de `proto/`, com `protoc` e `protoc-gen-go` v1.36.11 no `PATH`):
  1. `python3 -I protomerge.py ~/.cellar/bundles/whatsapp-<revisão>/modules .` mostra o relatório.
     Linhas com `!` pedem ajuste manual.
  2. O mesmo comando com `--write` grava os `.proto`. Uma segunda execução não deve achar diferenças.
  3. `protoc -I . --go_out=. --go_opt=paths=source_relative <arquivos alterados>` gera os `.pb.go`.
  4. `go build ./... && go test ./...` aqui, e `go build ./...` no wuzapi.
- **Versão anunciada:** `waVersion` em `store/clientpayload.go` passou de `2.3000.1044834443` a
  `2.3000.1055901559`. A variável `WA_VERSION` do wuzapi tem prioridade sobre esse valor.
- **MEX:** `waVersion` em `mex/spec.json` (e `WebVersion` em `mex/bindings.go`, gerado por
  `go generate ./mex`) passou de `2.3000.1044776264` a `2.3000.1055901559`. Os IDs das cinco consultas
  de catálogo foram trocados pelos do bundle (`WAWebQueryCatalogQuery`, `WAWebQueryCatalogProductQuery`,
  `WAWebQueryProductCollectionsQuery`, `WAWebQueryProductListCatalogJobQuery` e
  `WAWebQueryProductSingleCollectionQuery`). Entre os bundles `1053682356` e `1055901559` só o ID
  mudou nessas consultas. `DeleteNewsletter`, `BizCreateOrder` e `BizQueryOrder` já tinham o ID atual.
- **Não verificado:** as consultas de catálogo com os IDs novos não foram testadas com uma conta real.

## Como atualizar a base

1. Trocar o conteúdo desta pasta pela nova versão do fork.
2. Reaplicar os patches acima.
3. Se o fork passar a incluir a tradução do nome, apagar esta pasta, o `replace` do
   `go.mod` e a linha `COPY third_party` do `Dockerfile`, e atualizar o `require`.
