FROM golang:1.24.3-alpine

# Turn off cgo for a more static binary.
# Specify cache directory so that we can run as nobody to build the binary.
ENV CGO_ENABLED=0 XDG_CACHE_HOME=/tmp/.cache

USER nobody:nogroup

WORKDIR /go/src/github.com/sensiblecodeio/jump

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go install -v -buildvcs=false
