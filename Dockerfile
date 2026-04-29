# ── Build ──────────────────────────────────────────────────────────────────────
FROM golang:tip-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /app

# Cache go modules separately from source
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.buildDate=${BUILD_DATE}" \
      -o comply .

# ── Runtime ────────────────────────────────────────────────────────────────────
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/comply .

VOLUME ["/app/.complykit-evidence"]

EXPOSE 8080

LABEL org.opencontainers.image.title="ComplyKit" \
      org.opencontainers.image.description="Compliance scanner for AWS, GCP, Azure, Kubernetes and GitHub" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/nuvlabs/complykit"

ENTRYPOINT ["./comply"]
CMD ["serve", "--port", "8080"]
