PROJECT=go-saml-sso
VERSION=$(shell git describe --tags --exact-match --abbrev=0 2>/dev/null || echo $(shell git describe --tags $(shell git rev-list --tags --max-count=1))-dev)
DOCKER_IMAGE=harbor.whalebone.io/whalebone/$(PROJECT)

# HELP =================================================================================================================
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help: ## Display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


lint:  ## Run linter
	golangci-lint run
.PHONY: lint


build-docker:
	docker build -t $(DOCKER_IMAGE):$(VERSION) .
.PHONY: build-docker

