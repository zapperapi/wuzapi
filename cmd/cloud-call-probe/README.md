# cloud-call-probe

Prova de mídia entre o wuzapi e a Calling API da Meta (feature 028, T100). Usa o pion nas
condições do motor de ligações: ICE-full do nosso lado, cliente DTLS, Opus a 48 kHz, sem STUN.
O áudio recebido da Meta volta como eco: quem fala no telefone se ouve.

## Pré-requisitos

- Número da Cloud API com ligações ativas, fora de coexistência.
- Token com permissão `whatsapp_business_messaging`.
- Para ligação feita: o contato concedeu permissão de ligação.
- Saída UDP liberada na máquina. A Meta é ICE-lite com IP público, e o nosso lado inicia os
  checks, então a prova roda atrás de NAT.

As credenciais vão só por variável de ambiente, e o token nunca é impresso:

```sh
export META_ACCESS_TOKEN=...
export META_PHONE_NUMBER_ID=...
```

## Ligação recebida

A Meta derruba a ligação não atendida em 30 a 60 s. Para não colar o SDP à mão, aponte o
webhook do evento `calls.update` (ou o corpo da Meta) para o programa com `-listen`:

```sh
go run ./cmd/cloud-call-probe -mode incoming -listen :8088 -seconds 60 -record recebido.ogg
```

Sem `-listen`, cole o JSON do evento (ou o SDP puro, com `-call-id`) e termine com uma linha
vazia.

## Ligação feita

```sh
go run ./cmd/cloud-call-probe -mode outgoing -to 5511999990000 -listen :8088 -seconds 60
```

O programa manda o `connect` e espera o evento `connect` com a resposta SDP da Meta.

## Resultado

- **Entrada**: o programa conta os pacotes recebidos da Meta. `-record` grava o áudio em `.ogg`.
- **Saída**: confirme pelo ouvido, ouvindo o eco. A Meta derruba a ligação depois de 20 a 30 s
  sem mídia; se a ligação durou o tempo todo, a Meta recebeu os pacotes.

Registre o resultado no item 7 de `specs/028-operacao-e-ligacoes-cloud-api/verificacoes.md`.
