# Build Backend
ARG GOLANG_BUILD_IMAGE="${GOLANG_BUILD_IMAGE:-golang:1.23.4-alpine3.21}"
ARG ALPINE_BUILD_IMAGE="${ALPINE_BUILD_IMAGE:-alpine:3.21}"

FROM $GOLANG_BUILD_IMAGE AS builder

WORKDIR /app
COPY . /app

RUN go mod download
RUN cd /app && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -trimpath -o='encryptor-service' ./

FROM $ALPINE_BUILD_IMAGE

# Копируем бинарник из builder
COPY --from=builder /app/encryptor-service /app/encryptor-service
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/static /app/static

ENV USER root
WORKDIR /app
ENV LISTEN_PORT 8080
EXPOSE "${LISTEN_PORT:-8080}"

ENTRYPOINT /app/encryptor-service