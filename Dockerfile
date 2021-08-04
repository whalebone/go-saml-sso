#cert temporary image
FROM alpine:latest as certs
RUN apk add --no-cache ca-certificates

# build temporary image
FROM golang:1.16 as build

WORKDIR /go/src/github.com/whalebone/go-saml-sso
COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 go build

# final prod image
#FROM alpine:3.11
FROM scratch

WORKDIR /go/bin
ENV PATH=/bin
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /go/src/github.com/whalebone/go-saml-sso/go-saml-sso .
COPY --from=build /go/src/github.com/whalebone/go-saml-sso/adfs.neon .

ENTRYPOINT [ "./go-saml-sso" ]
