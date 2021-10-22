FROM golang:alpine
RUN --mount=type=cache,target=/var/cache/apk \
    apk --update add \
        build-base \
        gcc \
        libpcap-dev

WORKDIR /go/src/app
COPY go.mod go.sum . 
RUN go mod download
COPY main.go .
RUN go build

CMD ["go", "run", "."]
