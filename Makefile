.PHONY: help build test bench vet lint fmt cover fixtures clean

help:
	@echo "Targets:"
	@echo "  make build      Build the zenon-spv and fetch-bundle binaries"
	@echo "  make test       Run the test suite"
	@echo "  make bench      Repeat native verification benchmarks"
	@echo "  make vet        go vet ./..."
	@echo "  make lint       golangci-lint run"
	@echo "  make fmt        gofmt -w ."
	@echo "  make cover      Test with coverage report"
	@echo "  make fixtures   Regenerate internal/testdata JSON fixtures"
	@echo "  make clean      Remove build artifacts"

build:
	go build -o zenon-spv ./cmd/zenon-spv
	go build -o fetch-bundle ./cmd/fetch-bundle

test:
	go test ./...

bench:
	go test -run '^$$' -bench '^(BenchmarkNativeClient|BenchmarkRetainedCapacity|BenchmarkFlatContent|BenchmarkContentHashOrdering)$$' -benchmem -count=5 ./internal/conformance

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

fixtures:
	go run ./internal/testdata/genfixtures.go

clean:
	rm -f zenon-spv fetch-bundle coverage.out coverage.html
