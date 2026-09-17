# Implantação do softphone (feature `021-audio-bidirecional`)

O que a sessão de tempo real e a mídia ao vivo exigem da infraestrutura, e o que foi
verificado ao escrever a T003 e a T004.

---

## 1. WebSocket através do Traefik — **router público dedicado, restrito ao path**

Traefik encaminha `Upgrade: websocket` de forma transparente em qualquer router HTTP: o
upgrade é parte do protocolo HTTP/1.1 e não exige middleware, entrypoint dedicado nem
anotação própria para isso.

O que **não** dá para reaproveitar são os labels que já existem no serviço: `Server.url` é o
endereço interno, manager → wuzapi (Docker-internal, ex.: `http://api03:8080`), nunca
alcançável por um navegador. O endereço que o navegador usa é `Server.publicUrl`
(`resolveSoftphoneEndpoint`), e ele precisa de um router Traefik próprio, com `Host` público
e **restrito por `PathPrefix`** a `/softphone` — nunca um router genérico em `Host(...)` sem
prefixo, que exporia a API REST inteira daquele wuzapi (autenticada só pelo token por
instância, que não é secreto: é o próprio `instanceId`, usado publicamente em outros lugares
da plataforma):

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.wuzapi-softphone-<server>.rule=Host(`<server>.zapperhub.com`) && PathPrefix(`/softphone`)
  - traefik.http.routers.wuzapi-softphone-<server>.entrypoints=websecure
  - traefik.http.routers.wuzapi-softphone-<server>.tls=true
  - traefik.http.routers.wuzapi-softphone-<server>.tls.certresolver=certresolver
  - traefik.http.services.wuzapi-<server>.loadbalancer.server.port=8080
```

Sem middleware de `stripprefix`: o handler espera receber `/softphone` literalmente
(`routes.go`), então o `PathPrefix` aqui é só filtro, não reescrita.

Como cada servidor da frota é um nó próprio (não um serviço que o Swarm pode realocar entre
nós — as portas de mídia em `mode: host` já dependem disso), o serviço precisa de uma
constraint de `placement` fixando-o nesse nó (ex.: `node.labels.server == <server>`), e o
`Server.publicUrl`/DNS desse host devem apontar para um IP público **estável** (reservado no
provedor de nuvem), não o IP efêmero padrão da VM.

Duas condições continuam obrigatórias e são responsabilidade do ambiente:

- **TLS terminado no Traefik** (`entrypoints=websecure`, `tls.certresolver`), porque o
  navegador só permite captura de microfone em contexto seguro, e uma página `https` não abre
  socket `ws://`.
- **Sem timeout ocioso curto** no entrypoint. A sessão do atendente fica aberta sem tráfego
  entre chamadas; o `ping`/`pong` do protocolo existe para isso, mas um
  `respondingTimeouts.idleTimeout` agressivo no Traefik derruba a sessão antes.

## 2. Origem cruzada — **não é CORS, é a claim `origin` da credencial**

Achado da T003: o `wuzapi` não emite nenhum cabeçalho `Access-Control-*` hoje, e **não
precisa** emitir para o socket. Handshake de WebSocket não dispara preflight CORS; o navegador
manda o cabeçalho `Origin` e cabe ao servidor aceitar ou recusar.

Não existe mais uma variável de ambiente para isso (`SOFTPHONE_ALLOWED_ORIGINS` foi removida):
um único wuzapi hospeda várias instâncias, cada uma com o CRM de um cliente diferente, então
uma lista estática por servidor não tem como representar isso. `websocket.Accept` aceita
qualquer origem no handshake (`InsecureSkipVerify`), e a validação de verdade acontece logo
depois, em `authenticateSoftphone`: o cabeçalho `Origin` da conexão é comparado contra a claim
`origin` da credencial — estampada pelo `zapperapi-manager` a partir de `Instance.softphoneOrigin`
no momento em que a credencial é emitida. Sem essa origem cadastrada na instância, o manager
recusa emitir a credencial (`503 PROVIDER_UNAVAILABLE`); com ela cadastrada mas incompatível
com a página que abriu a conexão, o wuzapi recusa a sessão (`AGENT_TOKEN_INVALID`, a mesma
resposta de token adulterado — FR-009, não revela qual das duas causas foi).

## 3. Mídia: uma porta UDP e uma porta TCP

A mídia é WebRTC e **não** passa pelo Traefik. O `wuzapi` anuncia um candidato host com o IP
público do nó, e o navegador — atrás de NAT — abre o mapeamento de saída.

| Variável | Padrão | Papel |
|---|---|---|
| `SOFTPHONE_MEDIA_UDP_PORT` | `3478` | Porta única muxada para toda a mídia (`SetICEUDPMux`) |
| `SOFTPHONE_MEDIA_TCP_PORT` | `3479` | Rota de fuga ICE-TCP para redes que bloqueiam UDP |
| `SOFTPHONE_PUBLIC_IP` | — | IP público anunciado no SDP (`SetNAT1To1IPs`) |

**Uma porta, não uma faixa**: todas as sessões são multiplexadas, então não há regra dinâmica
de firewall nem faixa efêmera a liberar.

No Swarm, as duas portas precisam ser publicadas em **`mode: host`**. O modo `ingress`
(padrão) passa pela malha de roteamento e **substitui o IP de origem**, o que quebra o
casamento de candidatos ICE:

```yaml
ports:
  - target: 3478
    published: 3478
    protocol: udp
    mode: host
  - target: 3479
    published: 3479
    protocol: tcp
    mode: host
```

E ambas liberadas no security group para `0.0.0.0/0` — o atendente pode estar em qualquer
rede.

## 4. O que ainda depende de verificação em ambiente real

Nada acima exige acesso a produção para ser configurado, mas três coisas só se confirmam lá:

1. Que o entrypoint `websecure` não tem `idleTimeout` curto o bastante para derrubar uma
   sessão ociosa.
2. Que o IP em `SOFTPHONE_PUBLIC_IP` é de fato o IP de saída do nó, e não o de um NAT
   intermediário.
3. Que o security group libera UDP — restrição de UDP em VPC costuma passar despercebida até a
   primeira chamada sem áudio.

O Cenário 1 do `quickstart.md` é o teste que fecha os três de uma vez.
