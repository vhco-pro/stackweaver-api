FROM golang:1.26.6-alpine@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS builder
ENV GOPRIVATE=github.com/michielvha/stackweaver

ARG TARGETARCH
ARG TARGETOS=linux

WORKDIR /build
RUN apk add --no-cache git

COPY backend/go.mod backend/go.sum ./
RUN --mount=type=secret,id=netrc,target=/root/.netrc go mod download

COPY backend/ .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -o stackweaver-api ./cmd/api

# Runtime stage — distroless:nonroot eliminates all OS-level CVEs
# Includes ca-certificates and tzdata, runs as nonroot (UID 65534)
FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --from=builder /build/stackweaver-api /stackweaver-api
# No config.yaml is baked in. The API reads CONFIG_PATH, falls back to config/config.yaml, and
# runs on environment variables alone when neither resolves - which is how both the Helm chart
# and the Docker Compose bundle deploy it. Shipping the file made a config nothing loads part of
# a public image, complete with the repo's dev database password.

LABEL org.opencontainers.image.source="https://github.com/vhco-pro/stackweaver-api"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.description="Stackweaver API — Go backend for the Stackweaver DevOps platform"

ENTRYPOINT ["/stackweaver-api"]
