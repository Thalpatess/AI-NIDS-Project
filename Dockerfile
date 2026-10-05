FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN apk add --no-cache gcc musl-dev libpcap-dev
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -o /bin/nids ./cmd/nids
RUN CGO_ENABLED=1 GOOS=linux go build -o /bin/nids-api ./cmd/api

FROM alpine:3.19
RUN apk add --no-cache libpcap ca-certificates
WORKDIR /app
COPY --from=builder /bin/nids /usr/local/bin/nids
COPY --from=builder /bin/nids-api /usr/local/bin/nids-api
RUN chmod +x /usr/local/bin/nids /usr/local/bin/nids-api
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/nids"]
