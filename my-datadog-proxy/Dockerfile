# Étape de build
FROM golang:1.24.2 AS builder

COPY . /app
WORKDIR /app

RUN go mod tidy
RUN go build -o proxy .

 #Étape de runtime
FROM debian:bookworm-slim

# Install ca-certificates
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/proxy .

EXPOSE 8081

CMD ["./proxy"]
