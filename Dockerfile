FROM golang:latest

WORKDIR /app

COPY go.mod go.sum ./

# download the dependencies
RUN go mod download 


COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main .

RUN mv  main /

RUN rm -rf /app

EXPOSE 8080

CMD ["/main"]