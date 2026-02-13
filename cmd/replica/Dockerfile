FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /plc-replica ./cmd/replica

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /plc-replica /usr/local/bin/plc-replica
WORKDIR /data
ENTRYPOINT ["plc-replica"]
