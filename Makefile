# Makefile for building Fuzz-Aldrin AVS

GO = $(shell which go)
OUT = ./bin

build: deps
	@mkdir -p $(OUT) || true
	@echo "Building binaries..."
	go build -buildvcs=false -o $(OUT)/performer ./cmd/main.go
	go build -buildvcs=false -o $(OUT)/aggregator ./cmd/aggregator/
	go build -buildvcs=false -o $(OUT)/operator ./cmd/operator/
	go build -buildvcs=false -o $(OUT)/cli ./cmd/cli/

deps:
	GOPRIVATE=github.com/Layr-Labs/* go mod tidy

build/container:
	./.hourglass/scripts/buildContainer.sh

test:
	go test ./... -v -p 1

clean:
	rm -rf $(OUT)
