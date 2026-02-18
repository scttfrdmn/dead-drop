# Build stage
FROM golang:1.26 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dead-drop-server ./cmd/server

# Runtime stage
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /dead-drop-server /dead-drop-server

EXPOSE 8080

ENTRYPOINT ["/dead-drop-server"]
