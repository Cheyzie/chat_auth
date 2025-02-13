FROM golang:1.23 AS build

ENV GOPATH=/
WORKDIR /go/src

COPY ./ ./

RUN go mod download
RUN go build -o /bin/app ./cmd/main.go

FROM build as run
WORKDIR /go/bin
COPY --from=build /bin/app .
COPY .env .
CMD ["./app"]