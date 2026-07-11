# ───────────────────────── build ─────────────────────────
# Scout has zero third-party Go dependencies, so this builds fully offline.
FROM golang:1.23-bookworm AS builder
WORKDIR /build
COPY . .
ARG VERSION=2.0.0
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/scout .

# ───────────────────────── runtime ─────────────────────────
# Debian slim gives an agent a familiar, capable shell environment (GNU
# coreutils, apt, bash) plus the docker CLI and kubectl for controlling the
# host's Docker/Kubernetes via a mounted socket / kubeconfig.
FROM debian:bookworm-slim

ARG TARGETARCH=amd64
ARG DOCKER_VERSION=27.3.1
ARG KUBECTL_VERSION=v1.31.1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl git bash procps jq ripgrep less \
        openssh-client tar gzip nano vim-tiny; \
    rm -rf /var/lib/apt/lists/*; \
    # map Go arch -> download arch
    case "${TARGETARCH}" in \
        amd64) DKR_ARCH=x86_64; K_ARCH=amd64 ;; \
        arm64) DKR_ARCH=aarch64; K_ARCH=arm64 ;; \
        *) DKR_ARCH=x86_64; K_ARCH=amd64 ;; \
    esac; \
    # docker CLI (client only; talks to a mounted /var/run/docker.sock)
    curl -fsSL "https://download.docker.com/linux/static/stable/${DKR_ARCH}/docker-${DOCKER_VERSION}.tgz" -o /tmp/docker.tgz; \
    tar -xzf /tmp/docker.tgz -C /tmp; \
    mv /tmp/docker/docker /usr/local/bin/docker; \
    rm -rf /tmp/docker /tmp/docker.tgz; \
    # kubectl
    curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${K_ARCH}/kubectl" -o /usr/local/bin/kubectl; \
    chmod +x /usr/local/bin/kubectl; \
    docker --version; kubectl version --client=true || true

COPY --from=builder /out/scout /usr/local/bin/scout

# Default working dir for agent operations (mount your project here).
RUN mkdir -p /work /etc/scout
WORKDIR /work

# Config is optional; env vars work too. Mount /etc/scout/scout.yaml to override.
ENV SCOUT_PORT=8080 \
    SCOUT_WORKING_DIR=/work

EXPOSE 8080
ENTRYPOINT ["scout"]
