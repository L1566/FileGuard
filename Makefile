.PHONY: build test lint clean run-gateway run-policy run-audit run-kms run-agent run-riskservice

BINARY_DIR=bin

build:
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/gateway ./cmd/gateway
	go build -o $(BINARY_DIR)/policy ./cmd/policy
	go build -o $(BINARY_DIR)/audit ./cmd/audit
	go build -o $(BINARY_DIR)/kms ./cmd/kms
	go build -o $(BINARY_DIR)/agent ./cmd/agent
	go build -o $(BINARY_DIR)/riskservice ./cmd/riskservice

test:
	go test -race -v ./...

lint:
	golangci-lint run

clean:
	rm -rf $(BINARY_DIR)

run-gateway:
	go run ./cmd/gateway -config configs/gateway.yaml

run-policy:
	go run ./cmd/policy -config configs/policy.yaml

run-audit:
	go run ./cmd/audit -config configs/audit.yaml

run-kms:
	go run ./cmd/kms -config configs/kms.yaml

run-agent:
	go run ./cmd/agent -config configs/agent.yaml

run-riskservice:
	go run ./cmd/riskservice -config configs/riskservice.yaml

deps:
	go mod download
	go mod tidy