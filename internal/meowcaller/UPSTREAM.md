# meowcaller — fork vendorizado

Cópia interna de [`github.com/purpshell/meowcaller`](https://github.com/purpshell/meowcaller),
licença MIT (ver `LICENSE` neste diretório).

| | |
|---|---|
| **Commit de origem** | `27a3c6b18657614c9ec2ed16dfc497eff11de6ec` |
| **Vendorizado em** | 2026-09-04 |
| **Feature** | `020-chamadas-device` |

## Por que existe este fork

O `meowcaller` importa `go.mau.fi/whatsmeow`. O `wuzapi` roda sobre
`github.com/polymorfa/hypermeow`, um fork do whatsmeow com os caminhos de import
reescritos. `*whatsmeow.Client` e `*hypermeow.Client` são tipos distintos para o
compilador, então a biblioteca não pode ser consumida como dependência normal.

Um `replace go.mau.fi/whatsmeow => github.com/polymorfa/hypermeow` **não** resolve:
sob o `replace`, os imports internos do próprio `hypermeow` continuam apontando para
`github.com/polymorfa/hypermeow/...`, que o Go resolve como um segundo módulo. O
binário passaria a ter duas cópias de `types`, `binary` e `events`, e o `types.JID`
de um lado deixaria de ser o `types.JID` do outro.

Análise completa em `specs/020-chamadas-device/research.md` §R1 e §R2.

## O que foi copiado

Pacotes de biblioteca: raiz, `diag/`, `mlow/`, `relay/`, `rtp/`, `signaling/`,
`srtp/`, `stun/`, `util/` — com os respectivos `testdata/`.

**Excluídos de propósito:**

| Caminho | Motivo |
|---|---|
| `audio/malgo/` | Módulo Go separado, com CGO (miniaudio). É sink de alto-falante/microfone, usado só pelos exemplos. Excluí-lo mantém o build do `wuzapi` livre de CGO. |
| `examples/` | Binários de demonstração; únicos consumidores de `audio/malgo`. |
| `datasheets/`, `docs/`, `scripts/` | Documentação e ferramental do upstream. |
| `diag/extension/`, `diag/extension-server/` | Extensão de navegador em TypeScript. |

## Patch 1 — reescrita mecânica de imports

Aplicada a todos os `*.go` deste diretório:

```bash
find . -name "*.go" -type f -exec sed -i '' \
  -e 's|go\.mau\.fi/whatsmeow|github.com/polymorfa/hypermeow|g' \
  -e 's|github\.com/purpshell/meowcaller|wuzapi/internal/meowcaller|g' {} +
```

A paridade de API entre `hypermeow` e o whatsmeow upstream foi verificada símbolo a
símbolo para toda a superfície que o `meowcaller` consome (research §R1). Os pacotes
importados após a reescrita são exatamente: raiz, `binary`, `types`, `types/events`,
`proto/waE2E`, `store` e `util/log`.

## Patch 2 — gancho de interceptação de nós

**Arquivo**: `engine.go` · **Origem**: research §R2

O upstream (`installCallAckHook`) alcança o campo não exportado `nodeHandlers` do
`whatsmeow.Client` via `reflect` + `unsafe`. O próprio comentário do upstream marca
essa função como `NOT VALIDATED`.

O `hypermeow` **não tem** esse mapa — o despacho de nós é um `switch` em `handleNode`.
O hack falharia no guarda de layout. Em compensação, o `hypermeow` expõe o campo
público `Client.RawNodeHandler`, invocado em `handleFrame` para todo nó de entrada,
antes do despacho por tag e antes do descarte silencioso de `<ack>`.

O patch substitui a reflexão pelo gancho público. `reflect` e `unsafe` saem do arquivo.

Política de nós adotada:

- `<ack class="call">` — entregue ao engine, com `drop: true`. O `hypermeow` já
  ignora `<ack>`; descartar não muda nada para ele.
- `<call>` — entregue em cópia, com `drop: false`. Mantém `handleCallEvent` do
  `hypermeow` intacto, e com ele os eventos que a feature `018` repassa ao cliente.
- Qualquer outro nó passa sem cópia.

Duas restrições que o gancho impõe:

1. `RawNodeHandler` é **um campo, não uma lista**. Instalar por cima de outro gancho o
   desligaria sem deixar rastro, então `installRawNodeHandler` recusa quando já existe um.
2. Ele roda **na goroutine de recepção do socket**. O handler só classifica e entrega
   a um canal com buffer — bloqueá-lo trava a conexão da instância inteira. Fila cheia
   descarta o nó, com log: um engine travado custa nós de chamada, nunca o socket.

**Adição do fork — `stopRawNodeHandler`.** O upstream nunca remove o gancho, porque
seus clientes vivem o processo inteiro. O `wuzapi` monta um cliente por conexão de
instância, então sem teardown cada reconexão vazaria uma goroutine.

O desligamento fecha um canal `quit` dedicado e **não** fecha a fila de nós. Fechar a
fila competiria com uma invocação do handler ainda em voo na goroutine de recepção, e
enviar em canal fechado provoca panic — derrubando a conexão inteira para parar um
engine. Pelo mesmo motivo, `rawNodeLoop` recebe os canais **por parâmetro**: se lesse
os campos do struct, o teardown o deixaria em `range` sobre canal nil, que bloqueia
para sempre. Foi exatamente esse o defeito da primeira versão do patch.

## Patch 3 — auto-ack tipado desligável

**Arquivo**: `engine.go` · **Origem**: research §R2

Como o `<call>` não é descartado (patch 2), o `hypermeow` responde o `<ack>`. Sem
este patch, o engine responderia também, e o par receberia ack duplo.

O auto-ack do engine passa a ser desligável pela opção `WithTypedCallAcks(false)`, e é
assim que o `wuzapi` constrói o cliente. O ack tipado só é exigido pelo upgrade de
chamada para vídeo e pelas stanzas de controle de chamada em grupo — ambos fora do
escopo desta feature.

O campo interno é **negativo** (`suppressTypedCallAcks`) de propósito: assim o
zero-value significa comportamento do upstream tanto via `resolveConfig` quanto em
`&Client{...}` literal. Sem isso, os testes do upstream que constroem o `Client` na
mão passariam a exercitar silenciosamente o caminho do fork — foi o que quebrou
`TestRawGroupControlSendsTypedAckWithoutUpstreamDoubleHandling` na primeira tentativa.

## Como ressincronizar com o upstream

1. Buscar o commit novo em `github.com/purpshell/meowcaller`.
2. Recopiar os pacotes listados acima, mantendo as exclusões.
3. Reaplicar o patch 1 com o comando desta página.
4. Reaplicar os patches 2 e 3 em `engine.go` — são os únicos com divergência
   semântica, e só eles exigem leitura.
5. Atualizar o commit de origem e a data no topo deste arquivo.
6. `go build ./... && go vet ./... && go test ./...` em `wuzapi/`.

## Patch 4 — cherry-pick do PR #26 do upstream (bind em todos os relays)

**Arquivos**: `engine.go`, `engine_media.go`, `engine_relay_fanout.go` (novo)
**Origem**: `purpshell/meowcaller` PR #26, commit `340c889422`, **ainda aberto** em 2026-09-18

Corrige o defeito que deixava o atendente surdo: a saída funcionava, a entrada nunca chegava,
e o `rtp.jsonl` do diagnóstico sequer era criado — nenhum pacote de entrada classificado como
RTP, com STUN e SRTCP saudáveis.

**Causa**, nas palavras do autor do PR: telefones rodam eleição de relay do lado do cliente
logo após o accept e migram a mídia para o relay que mediram mais próximo. O
`getMediaRelayEndpoint` escolhe por heurística estática e acerta por sorte; errando, o relay
aceita a conexão, responde aos pings e nunca entrega mídia. Clientes Web não migram
(`enable_web_relay_connection_stagger`), e é por isso que ligar em um relay só parecia
funcionar quando testado a partir do Web.

**Correção**: conectar e alocar em **todos** os relays oferecidos numa chamada 1:1, transmitir
por broadcast, unir as recepções atrás de um filtro de repetição por `(SSRC, seq)` — com
bind-to-all o mesmo pacote chega uma vez por relay, e timestamp duplicado reinicia o buffer de
playout —, reenviar a cada relay o **seu** allocate no keepalive (os tokens são específicos por
relay e não podem ser broadcast), e responder sondas de `relaylatency` apenas para relays
presentes na oferta. Chamadas de grupo mantêm a semântica de relay único via `PrimarySend`.

**Só o primeiro commit do PR foi trazido.** Os outros três (toggles de vídeo, orientação CVO,
ofertas velhas da fila offline) não têm relação com este defeito.

**Ao ressincronizar:** se o PR #26 tiver sido aceito lá em cima, este patch some — vem no
próprio upstream. Se ainda estiver aberto, reaplicar o `340c889422` e rodar o Patch 1 nos três
arquivos, porque o arquivo novo chega com os imports do upstream.

**Validação:** não há vetores KAT para o salto do relay ao vivo (limitação que a documentação
do próprio repositório reconhece), então isto está na mesma classe de validação do resto do
código de relay — suíte completa verde, e a prova real é uma chamada com áudio nos dois
sentidos.
