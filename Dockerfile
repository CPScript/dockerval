# Multi-stage Docker build for dockerval
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Install git (needed for some Go modules)
RUN apk add --no-cache git

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o dockerval main.go

# Final stage - minimal image
FROM alpine:3.18

# Install ca-certificates for HTTPS requests to APIs
RUN apk --no-cache add ca-certificates

# Create non-root user for security
RUN addgroup -g 1001 dockerval && \
    adduser -D -s /bin/sh -u 1001 -G dockerval dockerval

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/dockerval /usr/local/bin/dockerval

# Make binary executable
RUN chmod +x /usr/local/bin/dockerval

# Switch to non-root user
USER dockerval

# Set default command
ENTRYPOINT ["dockerval"]
CMD ["--help"]

# Health check to ensure binary works
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD dockerval check || exit 1

# Labels for better image management
LABEL \
  org.opencontainers.image.title="Docker Compose Validator" \
  org.opencontainers.image.description="A comprehensive Docker Compose validation tool with AI assistance" \
  org.opencontainers.image.vendor="dockerval" \
  org.opencontainers.image.source="https://github.com/CPScript/dockerval" \
  org.opencontainers.image.version="1.0.0" \
  org.opencontainers.image.licenses="MIT"