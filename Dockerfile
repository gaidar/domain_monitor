FROM golang:1.22-alpine AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o domain_monitor

FROM alpine:latest
WORKDIR /app

COPY --from=build /app/domain_monitor .
COPY templates templates/
COPY static static/
COPY .env .

EXPOSE 8080
CMD ["./domain_monitor"]