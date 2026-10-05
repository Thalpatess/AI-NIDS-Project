FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN apk add --no-cache gcc musl-dev libpcap-dev
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -o /bin/nids ./cmd/nids

FROM alpine:3.19
RUN apk add --no-cache libpcap ca-certificates
WORKDIR /app
COPY --from=builder /bin/nids /usr/local/bin/nids
RUN chmod +x /usr/local/bin/nids
ENTRYPOINT ["/usr/local/bin/nids"]
