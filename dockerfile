FROM golang:1.24.4-alpine

WORKDIR /app

RUN apk --no-cache add ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

COPY certs /certs

RUN go build -o main .

EXPOSE 8443

CMD ["./main"]