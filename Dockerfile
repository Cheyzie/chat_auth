FROM golang:1.20

ENV GOPATH=/

COPY ./ ./

RUN apt-get update
RUN apt-get -y install postgresql-client
RUN curl -L https://github.com/golang-migrate/migrate/releases/download/v4.14.1/migrate.linux-amd64.tar.gz | tar xvz
RUN mv migrate.linux-amd64 $GOPATH/bin/migrate
RUN chmod +x check-out-db.sh

RUN go mod download
RUN go build -o app ./cmd/main.go

CMD ["./app"]