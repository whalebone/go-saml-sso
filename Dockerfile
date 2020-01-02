FROM golang:1.13
COPY . /go/src/github.com/whalebone/sso/code
WORKDIR /go/src/github.com/whalebone/sso/code
RUN CGO_ENABLED=0 go build cmd/main.go

FROM alpine:3.11
RUN apk add --no-cache ca-certificates
COPY --from=0 /go/src/github.com/whalebone/sso/code/main .
CMD ["./main"]
