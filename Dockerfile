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

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    netcat-openbsd \
    postgresql-client \
    openssl \
    curl \
    ffmpeg \
    libopus0 \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

ENV TZ="America/Sao_Paulo"
WORKDIR /app

COPY --from=builder /app/wuzapi         /app/
COPY --from=builder /app/static         /app/static/
COPY --from=builder /app/wuzapi.service /app/wuzapi.service

RUN chmod +x /app/wuzapi && \
    chmod -R 755 /app && \
    chown -R root:root /app

ENTRYPOINT ["/app/wuzapi", "--logtype=console", "--color=true"]
