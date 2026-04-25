FROM golang:tip-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o comply .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/comply .
VOLUME ["/app/.complykit-evidence"]
EXPOSE 8080
ENTRYPOINT ["./comply"]
CMD ["serve", "--port", "8080"]
