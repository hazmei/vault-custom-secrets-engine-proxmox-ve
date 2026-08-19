PLUGIN_NAME := vault-plugin-secrets-proxmox
PLUGIN_DIR := vault/plugins
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')
# Pin golangci-lint version so local (make lint) and CI (.github/workflows/ci.yml) agree.
# v2.12.2 is the FLOOR: `go run` builds golangci-lint at *its own* go.mod language level,
# so the pinned version must be a release whose go directive is >= this module's Go language
# version. Older releases (e.g. v2.1.6, v2.5.0) were built pre-1.25 and REFUSE this module
# even on Go 1.25.7. v2.12.2's go.mod requires go >= 1.25.0, so `go run` selects a >=1.25
# toolchain (observed: "switching to go1.25.13") and the resulting binary clears golangci-lint's
# build-version guard for this module.
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
