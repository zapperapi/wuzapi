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
- **WhatsApp Web 2.3000.1056475087:** o `WASmaxReceiptDeliverRPC` declara mais dois recibos de erro:
  `<error type="bot-unavailable"/>` e `<biz reason="restricted_country_non_member"/>` com
  `<error type="feature-incapable"/>`. O cliente oficial não muda o estado da mensagem para eles.
  `events.Receipt` leva `ErrorReason` (atributo `reason` do filho `<biz>`, lido por
  `parseReceiptErrorReason`). O wuzapi registra esses recibos no log e não envia webhook.

## 8. Status em grupo (`is_group_status`)

- **Arquivos:** `types/message.go` (`MsgMetaInfo.IsGroupStatus`) e `send.go` (`SendMessage`).
- **Problema:** não havia como marcar uma mensagem de grupo como status do grupo.
- **Evidência** (teste local, 2026-11-23): com `groupStatusMessageV2` e `<meta is_group_status="true">`,
  o servidor respondeu com `ack is_group_status="true"`, e o status apareceu no celular de um participante.
- **Mudança:** com `Meta.IsGroupStatus`, o nó `<meta>` leva `is_group_status="true"`. Quem chama
  embrulha a mensagem em `GroupStatusMessageV2` (no wuzapi, `handlers_groupstatus.go`).

## 9. IDs e formatos MEX de canal

- **Arquivos:** `newsletter.go`, `types/newsletter.go`, `newsletter_test.go` (novo) e
  `types/newsletter_test.go` (novo).
- **Problema:** as consultas de canal usavam IDs que não existem mais no WhatsApp Web
  (2.3000.1053682356 e 2.3000.1055901559), e três formatos eram diferentes dos atuais.
- **Mudança nos IDs** (módulos `WAWebMex*Newsletter*.graphql`):

  | Operação | ID anterior | ID atual |
  |---|---|---|
  | Consultar canal | `6563316087068696` | `27456920720571478` |
  | Consultar canal, resumido | `7272540469429201` | `26944199458535748` |
  | Listar inscritos | `6388546374527196` | `25399611239711790` |
  | Criar | `6234210096708695` | `25149874324715067` |
  | Seguir | `9926858900719341` | `24404358912487870` |
  | Deixar de seguir | `6392786840836363` | `9767147403369991` |
  | Atualizar | `7150902998257522` | `24250201037901610` |
  | Silenciar e reativar | `6274038279359549` e `6068417879924485` | `31938993655691868` (uma mutation só) |
  | Seguidores | `9800646650009898` | `27472091235714801` |
  | Recomendados | `7263823273662354` | `25806748772361516` |
  | Diretório | `6190824427689257` | `26125047313831973` |

- **Mudança nos formatos:**
  - **Criar:** a variável passou de `newsletter_input` para `input` (`WAWebMexCreateNewsletterJob`).
  - **Silenciar:** `NewsletterToggleMute` usa `xwa2_newsletter_update_user_setting`, com
    `input{newsletter_id, type: "MUTE_ADMIN_ACTIVITY", value: "ON"|"OFF"}`. `MUTE_ADMIN_ACTIVITY` é a
    configuração que o Web grava no `muteExpiration` do chat (`WAWebNewsletterUpdateUserSettingJob`).
  - **Consultar:** as variáveis levam `input.view_role` (`GUEST` por padrão), `fetch_wamo_sub`,
    `fetch_status_metadata` e `fetch_pinned_messages`. `fetch_full_image` só vai `true` na consulta por JID.
  - **Listar:** as variáveis levam `fetch_wamo_sub` e `fetch_status_metadata`, as duas `false`.
  - **Seguir, sair e silenciar:** a resposta é lida. O estado `DELETED` ou `NON_EXISTING` devolve
    `ErrNewsletterNotFound`, e `SUSPENDED` devolve `ErrNewsletterSuspended` (`WAWebMexJoinNewsletterJob`).
- **Função nova:** `UpdateNewsletter` altera nome, descrição e foto com `xwa2_newsletter_update`. Só os
  campos editados entram em `updates`; a foto vai em base64, e uma string vazia remove a descrição ou a
  foto (`WAWebNewsletterMetadataQueryJob`).
- **Mudança nos tipos:** as consultas atuais não devolvem `viewer_metadata.mute`. O estado vem em
  `viewer_metadata.settings`. `NewsletterViewerMetadata` ganhou `Settings` e preenche `Mute` a partir
  do item `MUTE_ADMIN_ACTIVITY`. `NewsletterThreadMetadata` ganhou `Handle`.
- **Não alterado:** os IDs da variante desktop (`*Desktop`). O bundle do Web não permite conferi-los, e o
  wuzapi usa o payload de navegador. Silenciar não tem ID de desktop e devolve erro nessa variante.
- **Evidência** (teste local com conta real, 2026-11-23, versão `2.3000.1055901559`): o servidor aceitou
  listar, consultar por JID e por convite, silenciar e reativar, seguir e sair, criar, apagar e atualizar
  (nome, descrição, foto e remoção de foto). Seguir um canal inexistente devolveu o estado `NON_EXISTING`.
- **Observado no teste:**
  - O servidor ainda aceita o ID antigo de listar (`6388546374527196`), e nele `viewer_metadata` traz `mute`.
  - Consultar por JID um canal que a conta não segue devolve o erro 405 `Not Allowed`. A consulta por
    convite funciona nesse caso.
  - O papel real (`owner`, `subscriber`) vem em `viewer_metadata.role` mesmo com `view_role: "GUEST"`.
  - A foto precisa ser JPEG quadrado. Um JPEG de 1000x500 devolveu o erro 400 `Bad Request`.
- **Evento de silenciar:** o servidor avisa a mudança por `xwa2_notify_newsletter_on_user_setting_change`
  (visto no teste de 2026-11-23), e não mais por `_on_mute_change`. `notification.go` converte o aviso de
  `MUTE_ADMIN_ACTIVITY` em `events.NewsletterMuteChange`; antes o evento nunca era emitido.
- **Não verificado:** seguidores, recomendados e diretório. Os IDs foram trocados, mas a
  biblioteca não tem função que os use.
  O evento `NewsletterMuteChange` vindo do aviso novo foi testado só com o JSON capturado, não ao vivo.

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
- **Teste dos IDs:** ver a seção 11.
- **Atualização para 2.3000.1056475087:** o mesmo procedimento, com o bundle `1056475087`.
  - Entraram 3 mensagens (`DraftMessageSync`, `ConversationDraft`, `DeviceCapabilities.DraftSync`),
    2 enums (`DraftMessageSync.Action` e `ClearReason`), 17 campos e 13 valores de enum. São os
    dados da sincronização de rascunho: `ProtocolMessage.draftMessageSync` (campo 43, tipo
    `DRAFT_MESSAGE_SYNC = 45`), `Conversation.draft` (71), `DeviceCapabilities.draftSync` (17) e
    `DeviceProps.HistorySyncConfig.supportDraftSync` (29). O wuzapi não anuncia `supportDraftSync`.
  - `VpcRequestMessage`: `requestID` (campo 2) saiu e `token` (campo 4, `bytes`) entrou.
  - `PrepareAddPeerDeviceSuccess` (`WAWebLabyrinthWaWasm`) recebeu `identityBindingBlob` e
    `bindingSigByLabyrinthDevice`.
  - `waVersion` em `store/clientpayload.go` e em `mex/spec.json` passou a `2.3000.1056475087`.
  - Nenhum ID de consulta MEX usado aqui mudou entre os bundles `1055901559` e `1056475087`.

## 11. Consultas de catálogo por HTTP

- **Arquivos:** `business.go` (`sendBusinessMex` e os construtores de variáveis) e
  `catalog_transport_test.go` (novo).
- **Problema:** `GetCatalog`, `GetCatalogProduct`, `GetCatalogProducts`, `GetProductCollections` e
  `GetProductCollection` iam pelo IQ `w:mex`. O servidor devolvia `400 Bad Request` com o ID novo,
  com o ID antigo e com um ID inexistente, para JID de telefone e para LID.
- **Causa:** o cliente oficial não usa `w:mex` nessas consultas. `WAWebRelayEnvironment` (ambiente
  `whatsapp_catalog`) faz `POST https://graph.whatsapp.com/graphql/catalog` com `access_token`,
  `doc_id` e `variables`.
- **Mudança:** `sendBusinessMex` chama `sendBusinessFacebookGraphQL` com o endpoint e o token de
  catálogo que a consulta de conformidade do lojista já usava. As variáveis não levam mais
  `variant_info_fields: {}`: o servidor recusava o objeto vazio com `noncoercible_variable_value`.
- **Evidência** (teste local com conta real, 2026-11-23, conta comercial sem catálogo):
  - Um ID inexistente devolve `The GraphQL document with ID ... was not found`. Os IDs novos e os
    antigos são aceitos.
  - `GetCatalog` devolve o código `2498052` (item não encontrado).
  - `GetProductCollections` devolve a lista vazia.
  - `GetCatalogProduct` com ID fictício devolve `2498053`. `GetProductCollection` devolve `2498052`
    (JID de telefone) ou `2498055` (LID).
  - `GetCatalogProducts` com ID fictício devolve um produto vazio com o mesmo ID.
- **Não verificado:** a resposta com produtos e coleções reais. Falta uma conta com catálogo.
- **Não alterado:** o JID vai como telefone. O Web envia o LID quando a flag
  `wa_catalog_graphql_use_lid_enabled` está ligada; o servidor aceitou os dois formatos.

## 12. Criação de grupo igual à do WhatsApp Web

- **Arquivos:** `group.go` (`CreateGroup` e `buildCreateGroupNode`, nova), `types/group.go`
  (`GroupMemberShareGroupHistoryMode`, novo) e `group_create_test.go` (novo).
- **Problema:** o nó `<create>` não tinha `member_share_group_history_mode` (havia um `TODO`). Os
  filhos também vinham numa ordem diferente da do cliente oficial.
- **Referência** (bundle `1055901559`):
  - `WAWebNewGroupFlow.react` começa com `memberShareGroupHistoryMode: true`.
  - `WAWebGroupCreateJob` converte `true` em `all_member_share` e `false` em `admin_share`, e sempre
    envia o campo.
  - `WASmaxGroupsCreateRPC` põe os campos de modo na frente dos participantes, porque
    `WASmaxMixins.mergeStanzas` coloca os filhos novos antes dos que já existem. Depois vêm
    `locked`, `announcement`, `parent`, `ephemeral`, `membership_approval_mode` e `linked_parent`.
  - `WAWebGroupCommunityJob` (criação de comunidade) não envia o campo.
- **Mudança:**
  - O grupo comum envia `<member_share_group_history_mode>all_member_share</...>`. O campo
    `ReqCreateGroup.MemberShareGroupHistoryMode` troca esse valor.
  - A comunidade (`IsParent`) não envia o campo.
  - Os filhos seguem a ordem do Web.
  - A montagem do nó ficou em `buildCreateGroupNode`, que os testes usam sem conexão.
- **Não alterado:** a criação de comunidade ainda envia `member_add_mode`, `ephemeral` e
  `membership_approval_mode`, e o Web não envia esses campos. Ela também põe
  `default_membership_approval_mode="request_required"` em toda comunidade, e o Web só põe esse
  atributo na comunidade fechada.
- **Evidência** (teste local com conta real, 2026-11-23):
  - `POST /group/create` criou o grupo com um participante.
  - A notificação `w:gp2` de criação devolveu `member_share_group_history_mode` com
    `all_member_share`.
  - O participante com privacidade restrita voltou com `403` e um código de convite.
  - A sessão continuou conectada depois da criação.

## 13. Administração de canal

- **Arquivos:** `newsletter_admin.go` (novo), `types/newsletter_admin.go` (novo) e
  `newsletter_admin_test.go` (novo).
- **Problema:** a biblioteca não tinha as operações de dono e administrador de canal.
- **Mudança:** funções novas, com os IDs e as variáveis dos módulos `WAWebMex*Newsletter*` do
  WhatsApp Web 2.3000.1055901559:

  | Função | Operação do Web | ID |
  |---|---|---|
  | `GetNewsletterFollowers` | `WAWebMexFetchNewsletterFollowersJobQuery` | `27472091235714801` |
  | `GetNewsletterAdminCount` | `WAWebMexFetchNewsletterAdminInfoJobQuery` | `26278439461859188` |
  | `GetNewsletterPendingAdminInvites` | `WAWebMexFetchNewsletterPendingInvitesJobQuery` | `28049623068067370` |
  | `CreateNewsletterAdminInvite` | `WAWebMexCreateNewsletterAdminInviteJobMutation` | `9387141988078609` |
  | `RevokeNewsletterAdminInvite` | `WAWebMexRevokeNewsletterAdminInviteJobMutation` | `9656078347839416` |
  | `AcceptNewsletterAdminInvite` | `WAWebMexAcceptNewsletterAdminInviteJobMutation` | `9580828702035549` |
  | `DemoteNewsletterAdmin` | `WAWebMexDemoteNewsletterAdminJobMutation` | `9880997548630971` |
  | `ChangeNewsletterOwner` | `WAWebMexChangeNewsletterOwnerJobMutation` | `9546742745432473` |
  | `PinNewsletterMessages` | `WAWebMexNewsletterPinMessagesJobMutation` | `27165709459706559` |
  | `UnpinNewsletterMessages` | `WAWebMexNewsletterUnpinMessagesJobMutation` | `28007176042216937` |
  | `GetNewsletterInsights` | `WAWebMexFetchNewsletterInsightsJobQuery` | `9853618868050977` |

- **Formatos:**
  - As operações sobre um usuário levam `user_id` com o LID (`WAWebLidMigrationUtils.toUserLidOrThrow`).
    Um JID de telefone devolve `ErrNewsletterUserNotLID`.
  - Fixar e desafixar levam `input.message_ids` com os ids de servidor como string
    (`WAWebNewsletterPinMessageAction`).
  - Os insights levam uma lista de métricas `{id, type, group_by, surface}`. O `id` é de quem pede e
    volta no resultado (`WAWebNewsletterInsight*Processors`).
  - `BuildNewsletterAdminInvite` monta a mensagem `newsletterAdminInviteMessage`, que os clientes
    enviam ao convidado depois de criar o convite (`WAWebNewsletterSendMsgAction`).
- **Evidência** (teste local com conta real, 2026-11-23, versão `2.3000.1055901559`): o servidor aceitou
  fixar e desafixar (`expiry_ts` 30 dias depois da publicação, e os outros aparelhos recebem
  `xwa2_notify_newsletter_on_metadata_update` com `pinned_messages`), listar seguidores e consultar
  administradores e convites pendentes.
- **Insights:** o servidor respondeu `400 Bad Request` em canais com 0 seguidores. O Web só pede insights
  com `channels_producer_insights_min_followers` seguidores (padrão 100 no bundle). A resposta com dados
  não foi vista.
- **Não verificado:** convidar, revogar, aceitar e remover administrador e transferir o canal. Exigem
  uma segunda conta.

## 14. Enquete, quiz e pergunta em canal

- **Arquivos:** `newsletter_content.go` (novo), `newsletter_content_test.go` (novo) e `send.go`
  (`SendMessage`, `sendNewsletter`, `getTypeFromMessage`, `getMediaTypeFromMessage`).
- **Problema:** `sendNewsletter` não mandava o nó `<meta>`, e `getTypeFromMessage` só reconhecia a
  enquete V1. O `BuildPollCreation` sempre gera V1 com `messageSecret`, que o WhatsApp Web não usa
  em canal.
- **Mudança:**
  - `sendNewsletter` anexa `<meta polltype="creation" contenttype="text"|"image">` na enquete e no
    quiz, e `<meta questiontype="question">` na pergunta (`WASmaxMessagePublishNewsletterRPC`).
  - `getTypeFromMessage` devolve `poll` para as versões V1, V2, V3, V5 e V6 da enquete. Isso vale
    também fora de canal.
  - `getTypeFromMessage` e `getMediaTypeFromMessage` desembrulham `QuestionMessage` e
    `QuestionReplyMessage`.
  - `SendMessage` não gera `messageSecret` quando o destino é um canal.
  - `BuildNewsletterPoll` gera a enquete sem `messageSecret`: V3 na escolha única e V1 na múltipla
    (`WAWebPollsGeneratePollCreationMessageProto`).
  - `BuildNewsletterQuiz` gera V3 com `pollType = QUIZ` e `correctAnswer`.
  - `BuildNewsletterQuestion` gera `questionMessage` com um `extendedTextMessage` marcado com
    `contextInfo.isQuestion` (`WAWebE2EProtoGenerator`).
- **Decisões sem evidência completa no bundle:**
  - O quiz sai com `polltype="creation"`, como o Web envia. O RPC também define `quiz_creation`,
    mas nenhum módulo do Web o usa.
  - `correctAnswer` leva só `optionName`. No Web, `optionHash` só é preenchido em enquete com imagem.
- **Evidência** (teste local com conta real, 2026-11-23): o servidor aceitou enquete de múltipla
  escolha, enquete de escolha única, quiz e pergunta, com `server_id` no ack. No celular do dono, os
  quatro aparecem certos, e o quiz fixado aparece com o ícone de troféu.
- **Atenção:** no bundle, o quiz e a pergunta dependem de configurações do servidor
  (`channels_quiz_sending_enabled`, a capacidade `QUESTIONS` do canal e
  `channels_question_sender_message_types_m1_enabled`). O canal de teste aceitou os dois; outros canais
  podem recusar.
- **Recebimento:** `message.go` (`parseMessageSource`) marca `IsFromMe` com o atributo `is_sender` das
  mensagens de canal, como o WhatsApp Web (`WAWebNewsletterMsgStanzaAdapters`: `fromMe: isSender`). Antes,
  o post feito pelo celular do dono chegava com `IsFromMe = false`. Teste com conta real em 2026-11-23:
  o post do celular chegou com `IsFromMe = true`.

## 15. Filho associado (`associatedChildMessage`)

- **Arquivos:** `types/events/events.go` (`Message`, `UnwrapRaw`) e `types/events/unwrap_test.go`
  (novo).
- **Problema:** `UnwrapRaw` não desembrulhava `associatedChildMessage`. A versão HD de uma foto,
  quando chega nesse invólucro, ficava sem mídia visível para quem trata `evt.Message`.
- **Mudança:** `UnwrapRaw` desembrulha `associatedChildMessage.message` depois dos invólucros de
  visualização única. O `messageContextInfo` de fora (com `messageAssociation`) passa para a mensagem
  de dentro quando ela não tem um próprio. O campo novo `IsAssociatedChild` marca a mensagem.
- **Evidência:** `WAWebE2EProtoGenerator` (função `$`) gera
  `{associatedChildMessage: {message}, messageContextInfo}`, e `WAWebFutureproofProtoUtils` desembrulha
  o campo. O Web só embrulha quando o ABProp `wa_web_wrap_associated_child_message_enabled` está ligado;
  sem ele, o filho chega como `imageMessage` ou `videoMessage` comum, com o mesmo `messageAssociation`.
- **Não testado com conta real.**

## 16. Link de convite e subgrupos por MEX

- **Arquivos:** `group_mex.go` (novo), `group_mex_test.go` (novo), `group.go` (`GetGroupInviteLink`,
  `GetSubGroups` e `getSubGroupsIQ`, nova) e `types/group.go` (`CommunitySubGroup`, novo).
- **Problema:** o WhatsApp Web 2.3000.1055901559 não usa mais o IQ get `<invite/>` para ler o link
  de convite, nem o IQ `<sub_groups/>` para listar os grupos de uma comunidade. As duas consultas
  passaram para MEX.
- **Referência** (bundle `1055901559`):
  - **Link:** `WAWebMexFetchGroupInviteCodeJob`, ID `29247029834912157`, variáveis
    `{id, query_context: "INVITE_CODE"}`. A resposta é `xwa2_group_query_by_id.invite_code`.
  - **Revogar:** `WAWebGroupInviteJob.resetGroupInviteCode` continua com o IQ set `<invite/>`.
  - **Subgrupos:** `WAWebMexFetchAllSubgroupsJob`, ID `9935467776504344`, variáveis
    `{group_id, query_context, sub_group_hint_id}`. `WAWebQuerySubGroupAction` usa
    `query_context: "INTERACTIVE"` e não manda `sub_group_hint_id` quando não há grupo de referência.
    A resposta traz `default_sub_group` (grupo de avisos) e `sub_groups.edges[].node`, com `id`,
    `subject{value, creation_time}`, `properties{general_chat, hidden_group,
    membership_approval_mode_enabled}` e `membership_approval_requests.total_count`.
- **Mudança:**
  - `GetGroupInviteLink` sem `reset` consulta por MEX. Com `reset`, continua no IQ set.
  - `GetCommunitySubGroups` (nova) consulta por MEX e devolve `types.CommunitySubGroup`: o
    `GroupLinkTarget` de antes, mais `IsGeneralChat`, `IsHidden`, `MembershipApprovalMode` e
    `HasMembershipRequest`. O grupo de avisos vem primeiro, como no Web.
  - `GetSubGroups` mantém a assinatura e passa a usar `GetCommunitySubGroups`.
  - Os erros 401, 403 e 404 do MEX viram os mesmos erros do IQ (`ErrGroupInviteLinkUnauthorized` ou
    `ErrIQNotAuthorized`, `ErrNotInGroup` e `ErrGroupNotFound`).
  - Com qualquer outro erro do MEX (formato `argo`, plataforma sem o ID, erro 400, resposta
    incompleta), as duas funções registram um aviso e refazem a consulta pelo IQ antigo. No caso dos
    subgrupos, a resposta do IQ só preenche JID, nome e `IsDefaultSubGroup`.
- **Evidência** (teste local com conta real, 2026-11-23, versão `2.3000.1055901559`):
  - O servidor aceitou as duas consultas MEX. O log não teve nenhuma volta ao IQ.
  - **Link:** a resposta foi `{"xwa2_group_query_by_id":{"__typename":"XWA2GroupRegularGroup",
    "id":"…@g.us","invite_code":"…"}}`. Depois do reset pelo IQ set, a consulta MEX devolveu o código novo.
  - **Subgrupos:** `__typename` `XWA2CommunityGroup`, com o grupo de avisos em `default_sub_group` e
    o outro grupo em `sub_groups.edges`. O `id` vem com o JID completo e `creation_time` vem como
    string (`"1774146242"`).
  - **Grupo inexistente:** as duas consultas devolveram `data.xwa2_group_query_by_id: null` com o erro
    `404 Not Found`, que virou `ErrGroupNotFound`.
  - **Grupo comum em `GetCommunitySubGroups`:** a resposta veio com `__typename`
    `XWA2GroupRegularGroup` e o erro "not a community".
  - A sessão continuou conectada depois dos testes.
- **Não testado:** o erro 401 (link pedido por quem não é administrador) e o 403 (conta fora do grupo).

## 17. Tempo de fila da oferta de chamada

- **Arquivos:** `call.go` (`handleCallEvent`) e `types/events/call.go` (`CallOffer.Queued`).
- **Problema:** o cliente oficial não toca uma oferta de chamada que ficou 90 segundos ou mais na
  fila do servidor, nem uma oferta com o filho `<silence reason="...">`
  (`WAWebVoipCallOfferRingWindow` e `WAWebVoipCallOfferStanzaParser`, WhatsApp Web
  2.3000.1056475087). O tempo de fila vem no atributo `e` do nó `<call>`, em segundos. O
  hypermeow não lia esse atributo.
- **Mudança:** `events.CallOffer` leva `Queued` (`time.Duration`, zero quando o atributo falta).
  O motor de chamadas do wuzapi (`internal/meowcaller/offer_ring_window.go`) não atende nem toca
  uma oferta 1:1 vencida ou silenciada. A oferta de chamada em grupo não mudou.

## Como atualizar a base

1. Trocar o conteúdo desta pasta pela nova versão do fork.
2. Reaplicar os patches acima.
3. Se o fork passar a incluir a tradução do nome, apagar esta pasta, o `replace` do
   `go.mod` e a linha `COPY third_party` do `Dockerfile`, e atualizar o `require`.
