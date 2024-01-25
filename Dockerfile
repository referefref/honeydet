FROM golang:1.21 as builder

WORKDIR /app
RUN git clone https://github.com/referefref/honeydet.git .
RUN go mod download
RUN CGO_ENABLED=1 GOOS=linux go build -o honeydet
FROM debian:latest
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /root/
COPY --from=builder /app/honeydet .
COPY --from=builder /app/assets ./assets
COPY --from=builder /app/index.html .
COPY --from=builder /app/signatures.yaml .

EXPOSE 8888

CMD ["./honeydet", "-w"]
