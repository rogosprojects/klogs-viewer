# Use the official Golang image as the base image
FROM golang:1.23-alpine AS builder

ARG VERSION=-dev
# Set the Current Working Directory inside the container
WORKDIR /app

COPY go.mod go.sum main.go ./
COPY templates/ templates/

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Build the Go app
RUN go build -o main -ldflags="-X 'main.Version=${VERSION}'" .

FROM alpine:latest

# Set the Current Working Directory inside the container
WORKDIR /app

COPY --from=builder /app/main .

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
ENTRYPOINT ["./main"]