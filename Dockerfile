FROM golang:1.27rc2-alpine@sha256:dcbb18cc5fa1082364dc6aa95224b6b55429d09cbb9631a053d8064c1c367300 AS builder
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
COPY --from=builder /build/config /etc/iac/config

LABEL org.opencontainers.image.source="https://github.com/vhco-pro/stackweaver-api"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.description="Stackweaver API — Go backend for the Stackweaver DevOps platform"

ENTRYPOINT ["/stackweaver-api"]
