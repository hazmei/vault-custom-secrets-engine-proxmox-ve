PLUGIN_NAME := vault-plugin-secrets-proxmox
PLUGIN_DIR := vault/plugins
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: build
build:
	@mkdir -p $(PLUGIN_DIR)
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/vault-plugin-secrets-proxmox

.PHONY: test
test:
	go test -v ./...

.PHONY: testacc
testacc:
	VAULT_ACC=1 go test -v ./... -run TestAcc

.PHONY: fmt
fmt:
	gofmt -s -w $(GO_FILES)

.PHONY: lint
lint:
	golangci-lint run

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -rf $(PLUGIN_DIR) bin/ dist/
