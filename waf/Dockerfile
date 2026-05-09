FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /waf ./cmd/waf

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /waf /usr/local/bin/waf
COPY configs/ /etc/waf/configs/

ENV WAF_CONFIG_PATH=/etc/waf/configs/config.yaml
EXPOSE 8080 6060

ENTRYPOINT ["waf"]
