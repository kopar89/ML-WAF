.PHONY: build run test lint clean docker-build docker-up docker-down

APP_NAME = waf

build:
	go build -o bin/$(APP_NAME) ./cmd/$(APP_NAME)

run:
	go run ./cmd/$(APP_NAME)

test:
	go test -v -race -count=1 ./...

test-cover:
	go test -v -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ coverage.out coverage.html

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

tidy:
	go mod tidy

vendor:
	go mod vendor

bench:
	go test -bench=. -benchmem ./...
