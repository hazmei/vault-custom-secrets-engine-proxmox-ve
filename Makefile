PLUGIN_NAME := vault-plugin-secrets-proxmox
PLUGIN_DIR := vault/plugins
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')
# Pin golangci-lint version so local (make lint) and CI (.github/workflows/ci.yml) agree.
# `go run @version` builds with the LOCAL Go toolchain, which is fine because go.mod
# requires Go >= 1.25.7 anyway; contributors on older Go must upgrade regardless.
GOLANGCI_LINT_VERSION ?= v2.12.2

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
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -rf $(PLUGIN_DIR) bin/ dist/
