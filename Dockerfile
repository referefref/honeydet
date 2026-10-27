FROM golang:1.26 AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o honeydet

FROM debian:stable-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/honeydet /usr/local/bin/honeydet
COPY --from=builder /app/signatures.yaml /usr/share/honeydet/signatures.yaml

EXPOSE 8888

CMD ["honeydet", "-w", "-db", "/root/data/scans.db"]
