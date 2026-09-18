# syntax=docker/dockerfile:1
FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install build dependencies
# libopus-dev: transcodificacao Opus da perna do navegador (feature 021, research R3).
# A perna do WhatsApp e MLow, em Go puro; a do navegador e Opus, e nao existe codificador
# Opus maduro em Go puro. CGO ja esta habilitado abaixo.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    pkg-config \
    libopus-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ENV CGO_ENABLED=1
RUN go build -o wuzapi

FROM debian:bookworm-slim

# Dependências de execução, numa camada só.
#
# Havia duas camadas de `apt-get` aqui, e a primeira instalava `ca-certificates` que a
# segunda reinstalava — camada inteira por nada.
#
# `postgresql-client` e `netcat-openbsd` saíram: o binário fala com o Postgres pelo driver
# Go e nenhum caminho do código, do entrypoint ou de script invoca `psql` ou `nc`. `curl` e
# `openssl` ficam por serem pequenos e úteis para diagnosticar de dentro do contêiner.
#
# `ffmpeg` fica porque é usado de verdade: `helpers.go` chama `exec.Command("ffmpeg", ...)`
# na conversão de figurinhas. Ele é o grosso desta imagem — cortá-lo exige trocar o pacote
# do Debian por um binário estático, o que muda codecs e pede teste próprio.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    curl \
    ffmpeg \
    libopus0 \
    tzdata \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV TZ="America/Sao_Paulo"
WORKDIR /app

# Permissões no próprio COPY, e não num RUN depois.
#
# Um `chmod -R /app` posterior reescreve tudo o que veio acima numa camada nova: o binário e
# o `static` viajavam duas vezes em cada deploy. Com `--chmod` a camada é uma só. O dono já
# é root por padrão — não há `USER` neste estágio —, então o `chown` também era redundante.
COPY --from=builder --chmod=755 /app/wuzapi         /app/
COPY --from=builder --chmod=755 /app/static         /app/static/
COPY --from=builder --chmod=755 /app/wuzapi.service /app/wuzapi.service

ENTRYPOINT ["/app/wuzapi", "--logtype=console", "--color=true"]
