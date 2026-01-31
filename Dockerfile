# Alpine 3.21 as base for builder to manually install Go 1.25.6
FROM alpine:3.21 AS builder

ARG VERSION=-dev

# Install build dependencies and Go 1.25.6
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache git ca-certificates && \
    rm -rf /var/cache/apk/*

# Download and install Go 1.25.6 from official source
RUN wget -q https://go.dev/dl/go1.25.6.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.25.6.linux-amd64.tar.gz && \
    rm go1.25.6.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV GOBIN="/go/bin"

# Set the Current Working Directory inside the container
WORKDIR /app

COPY go.mod go.sum main.go ./
COPY templates/ templates/

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Build the Go app with static linking for better security
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -a -installsuffix cgo \
    -ldflags="-X 'main.Version=${VERSION}' -w -s" \
    -o main .

FROM alpine:3.21

# Install security updates and CA certificates
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata && \
    rm -rf /var/cache/apk/*

# Create non-root user for better security
RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup appuser

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/main .

# Change ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
ENTRYPOINT ["./main"]