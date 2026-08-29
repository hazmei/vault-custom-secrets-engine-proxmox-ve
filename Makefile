PLUGIN_NAME := vault-plugin-secrets-proxmox
PLUGIN_DIR := vault/plugins
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*')
# Pin golangci-lint version so local (make lint) and CI (.github/workflows/ci.yml)
# agree — the CI copy is the golangci-lint-action `version:` input.
# v2.12.2 is the FLOOR: `go run` builds golangci-lint at *its own* go.mod language level,
# so the pinned version must be a release whose go directive is >= this module's Go language
# version. Older releases (e.g. v2.1.6, v2.5.0) were built pre-1.25 and REFUSE this module
# even on Go 1.25.7. v2.12.2's go.mod requires go >= 1.25.0, so `go run` selects a >=1.25
# toolchain (observed: "switching to go1.25.13") and the resulting binary clears golangci-lint's
# build-version guard for this module.
GOLANGCI_LINT_VERSION ?= v2.12.2
VERIFY_PLUGIN_DIR ?= /etc/vault/plugins

.PHONY: build
build:
	@mkdir -p $(PLUGIN_DIR)
	go build -o $(PLUGIN_DIR)/$(PLUGIN_NAME) ./cmd/vault-plugin-secrets-proxmox

.PHONY: test
test:
	go test -v ./...

.PHONY: testacc
testacc:
	@missing=""; \
	[ -n "$$PVE_ADDR" ] || missing="$$missing PVE_ADDR"; \
	[ -n "$$PVE_TOKEN_ID" ] || missing="$$missing PVE_TOKEN_ID"; \
	[ -n "$$PVE_TOKEN_SECRET" ] || missing="$$missing PVE_TOKEN_SECRET"; \
	[ -n "$$PVE_TEST_GROUP" ] || missing="$$missing PVE_TEST_GROUP"; \
	[ -n "$$PVE_BEHAVIORAL_PATH" ] && [ "$$PVE_BEHAVIORAL_PATH" != "/version" ] || missing="$$missing PVE_BEHAVIORAL_PATH"; \
	[ -n "$$PVE_BEHAVIORAL_MARKER" ] || missing="$$missing PVE_BEHAVIORAL_MARKER"; \
	if [ "$$PVE_ROTATE_ROOT_ACC" = "1" ]; then \
		[ -n "$$PVE_ROTATE_BOOTSTRAP_TOKEN_ID" ] || missing="$$missing PVE_ROTATE_BOOTSTRAP_TOKEN_ID"; \
		[ -n "$$PVE_ROTATE_BOOTSTRAP_TOKEN_SECRET" ] || missing="$$missing PVE_ROTATE_BOOTSTRAP_TOKEN_SECRET"; \
		[ -n "$$PVE_ROTATE_PROVISIONER_GROUP" ] || missing="$$missing PVE_ROTATE_PROVISIONER_GROUP"; \
	fi; \
	if [ -n "$$missing" ]; then \
		echo "missing or invalid required acceptance environment variables:$$missing" >&2; \
		echo "set these before running make testacc; optional variables are not required" >&2; \
		exit 1; \
	fi
	VAULT_ACC=1 go test -count=1 -v -timeout=30m ./... -run TestAcc

.PHONY: fmt
fmt:
	gofmt -s -w $(GO_FILES)

.PHONY: lint
lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/*.sh; \
	else \
		echo "shellcheck not installed; skipping shell script lint"; \
	fi

.PHONY: verify-artifact
verify-artifact:
	EXPECTED_SHA="$(EXPECTED_SHA)" EXPECTED_OWNER="$(EXPECTED_OWNER)" \
	PLUGIN_DIR="$(VERIFY_PLUGIN_DIR)" scripts/verify-plugin-artifact.sh

.PHONY: smoke
smoke:
	scripts/verify-plugin-artifact-smoke.sh

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -rf $(PLUGIN_DIR) bin/ dist/ .smoke-tmp/
