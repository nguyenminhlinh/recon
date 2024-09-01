FROM golang:1.23.0 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main .

#
RUN apk add --no-cache git make && \
    git clone https://github.com/ffuf/ffuf.git /app/ffuf && \
    cd /app/ffuf && \
    make

CMD ["./main"]