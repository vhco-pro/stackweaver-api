FROM golang:1.26-alpine AS builder
ENV GOPRIVATE=github.com/michielvha/stackweaver

ARG IMAGE_NAME=stackweaver-api
ARG TARGETARCH
ARG TARGETOS=linux

WORKDIR /build

# Copy go modules first for caching
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=secret,id=netrc,target=/root/.netrc go mod download

# Copy source code
COPY backend/ .

# Build the API binary
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -o ${IMAGE_NAME} ./cmd/api

# Runtime stage
FROM alpine:3.23

ARG IMAGE_NAME=stackweaver-api
ENV IMAGE_NAME=${IMAGE_NAME}

# Install runtime dependencies
RUN apk add --no-cache ca-certificates wget git

# Create non-root user
RUN addgroup -g 1001 ${IMAGE_NAME} && \
    adduser -D -u 1001 -G ${IMAGE_NAME} ${IMAGE_NAME}

# Copy binary
COPY --from=builder /build/${IMAGE_NAME} /usr/local/bin/${IMAGE_NAME}
RUN chmod +x /usr/local/bin/${IMAGE_NAME}

# Copy config
COPY backend/config /etc/iac/config

USER ${IMAGE_NAME}
WORKDIR /home/${IMAGE_NAME}

LABEL org.opencontainers.image.source="https://github.com/vhco-pro/stackweaver-api"
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.description="Stackweaver API — Go backend for the Stackweaver DevOps platform"

ENTRYPOINT ["/bin/sh", "-c", "/usr/local/bin/${IMAGE_NAME}"]
