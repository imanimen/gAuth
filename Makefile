BINARY := main
SWAG := $(shell go env GOPATH)/bin/swag

.PHONY: build run test test-coverage vet fmt lint swag verify clean docker-build

build:
	go build -o $(BINARY) .

run:
	go run .

test:
	go test ./...

test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	@go build ./...

swag:
	$(SWAG) init

verify: fmt vet build test

clean:
	@rm -f $(BINARY) coverage.out

docker-build:
	docker build -t gauth .
