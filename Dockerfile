FROM golang:alpine AS builder

WORKDIR /build
COPY main.go .
RUN go mod init scout && \
    go mod tidy && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o scout main.go

# ─────────────────────────────────────────────────────────
# Runtime: Alpine with read-only CLI tools
# ─────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache \
    # Core utils
    coreutils findutils grep gawk sed diffutils \
    # File inspection
    file tree \
    # Git (read-only ops)
    git \
    # Modern alternatives
    ripgrep fd bat \
    # JSON
    jq \
    # Misc
    xxd \
    && adduser -D -u 1000 scout

COPY --from=builder /build/scout /usr/local/bin/scout

# Drop to non-root
USER scout

ENTRYPOINT ["scout"]
