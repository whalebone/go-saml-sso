#cert temporary image
FROM alpine:latest AS certs
RUN apk add --no-cache ca-certificates && update-ca-certificates -v

# build temporary image
FROM golang:1.22 AS build

WORKDIR /go/src/github.com/whalebone/go-saml-sso
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . ./
RUN CGO_ENABLED=0 go build

# final prod image
FROM scratch

WORKDIR /go/bin
ENV PATH=/bin
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /go/src/github.com/whalebone/go-saml-sso/go-saml-sso .
COPY --from=build /go/src/github.com/whalebone/go-saml-sso/adfs.neon .

# Optionally uncomment to build metadata files into the image
#COPY --from=build /go/src/github.com/whalebone/go-saml-sso/metadata/*.xml /metadata/

ENTRYPOINT [ "./go-saml-sso" ]
