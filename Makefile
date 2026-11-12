.PHONY: test race vet build demo bench check

test:
	go test ./... -count=1 -timeout 180s

race:
	go test -race -count=1 ./... -timeout 300s

vet:
	go vet ./...

build:
	go build -o bin/ ./cmd/...

demo:
	go run ./cmd/gateway demo

bench:
	go run ./cmd/gateway bench

check:
	go run ./cmd/gateway check
	go run ./cmd/registry check
	go run ./cmd/approval-service check
	go run ./cmd/audit-collector check
