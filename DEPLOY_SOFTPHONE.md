# Implantação do softphone (feature `021-audio-bidirecional`)

O que a sessão de tempo real e a mídia ao vivo exigem da infraestrutura, e o que foi
verificado ao escrever a T003 e a T004.

---

## 1. WebSocket através do Traefik — **nenhum label novo é necessário**

Traefik encaminha `Upgrade: websocket` de forma transparente em qualquer router HTTP: o
upgrade é parte do protocolo HTTP/1.1 e não exige middleware, entrypoint dedicado nem
anotação. Os labels existentes do serviço já servem `wss://<Server.url>/softphone`.

Duas condições continuam obrigatórias e são responsabilidade do ambiente:

- **TLS terminado no Traefik** (`entrypoints=websecure`, `tls.certresolver`), porque o
  navegador só permite captura de microfone em contexto seguro, e uma página `https` não abre
  socket `ws://`.
- **Sem timeout ocioso curto** no entrypoint. A sessão do atendente fica aberta sem tráfego
  entre chamadas; o `ping`/`pong` do protocolo existe para isso, mas um
  `respondingTimeouts.idleTimeout` agressivo no Traefik derruba a sessão antes.

## 2. Origem cruzada — **não é CORS, é a checagem de `Origin`**

Achado da T003: o `wuzapi` não emite nenhum cabeçalho `Access-Control-*` hoje, e **não
precisa** emitir para o socket. Handshake de WebSocket não dispara preflight CORS; o navegador
manda o cabeçalho `Origin` e cabe ao servidor aceitar ou recusar.

Consequência prática: `websocket.Accept` do `coder/websocket` **recusa origem cruzada por
padrão**. A página do CRM roda em outro domínio, então a lista de origens aceitas é
configuração obrigatória, não opcional:

```
SOFTPHONE_ALLOWED_ORIGINS=https://crm.cliente.com,https://app.outrocliente.com.br
```

Vazio significa recusar toda origem cruzada — falha fechada, de propósito. Curinga (`*`) é
aceito apenas para desenvolvimento local e **não** deve chegar a produção: quem controla a
origem controla quem consegue abrir sessão com uma credencial vazada.

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
