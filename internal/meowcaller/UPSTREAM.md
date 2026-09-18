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

## Patch 4 — assinatura dos fluxos do par na chamada 1:1

**Hipótese em teste, não correção confirmada.** Em produção o relay respondia aos pings e
nunca encaminhava a mídia do contato: nenhum pacote com tamanho de áudio chegava ao nó, e o
`first RTP-classified packet from relay` nunca disparava. O atendente falava e era ouvido; o
contato falava e não era.

O `<relay>` de uma chamada 1:1 nomeia o par com um pid (`peer_pid="1"` ao lado de
`self_pid="2"`, com o `<participant pid="1" jid="…"/>` correspondente), igual ao que faz numa
chamada de grupo. O upstream usa esse número apenas para localizar o JID do par em
`parseRelayData` e o descarta; o allocate da 1:1 sai por
`BuildWasmStunAllocateRequestWithStreamSsrcs`, declarando só os nossos nove streams, enquanto
`BuildWasmStunAllocateRequestWithGroupSubscriptions` — que assina os fluxos de um participante
— só é usado no caminho de grupo.

Este patch guarda `peerPID`/`hasPeerPID` no `relayData` e faz o allocate da 1:1 assinar o par
quando ele está identificado (`buildCallAllocate`, `engine_media.go`). `hasPeerPID` existe
porque **pid 0 é válido** — ofertas reais trazem `<participant pid="0">`, então ausência não
pode ser inferida do valor.

Sem pid de par o allocate é byte a byte o de antes, e há teste fixando isso
(`relay_subscription_test.go`), para que o caminho da `020` não mude por tabela.

**O que ainda não está provado:** em pelo menos uma chamada observada o áudio do contato
chegou sem esta assinatura, então ela não pode ser condição estritamente necessária. Se o
sintoma persistir com o patch aplicado, a causa é outra e este patch deve ser revisto — não
mantido por inércia.
