# Version management
VERSION_FILE := version/version.go

# Get current version from version.go
CURRENT_VERSION := $(shell grep -E "Major|Minor|Patch" $(VERSION_FILE) | grep -E "[0-9]+" -o | paste -sd "." -)

# Git information
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S_UTC')

# Go build flags
LDFLAGS := -X github.com/lattiq/connectors/version.GitCommit=$(GIT_COMMIT) \
           -X github.com/lattiq/connectors/version.GitBranch=$(GIT_BRANCH) \
           -X "github.com/lattiq/connectors/version.BuildTime=$(BUILD_TIME)"

# Build commands
.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" ./...

.PHONY: install
install:
	go install -ldflags "$(LDFLAGS)" ./...

# Development commands
.PHONY: dev
dev:
	go run ./...

.PHONY: test
test:
	go test ./...

.PHONY: test-verbose
test-verbose:
	go test -v ./...

.PHONY: coverage
coverage:
	go test -cover ./...

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint: fmt vet

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: verify
verify:
	go mod verify

.PHONY: clean
clean:
	rm -rf bin/
	go clean ./...

# Version management
.PHONY: version
version:
	@echo "Current version: v$(CURRENT_VERSION)"
	@echo "Git commit: $(GIT_COMMIT)"
	@echo "Git branch: $(GIT_BRANCH)"

.PHONY: release-patch
release-patch:
	@echo "Current version: v$(CURRENT_VERSION)"
	@CURRENT_PATCH=$$(grep "Patch = " $(VERSION_FILE) | grep -o "[0-9]*"); \
	NEW_PATCH=$$(expr $$CURRENT_PATCH + 1); \
	sed -i.bak "s/Patch = [0-9]*/Patch = $$NEW_PATCH/" $(VERSION_FILE); \
	rm -f $(VERSION_FILE).bak; \
	NEW_VERSION=$$(grep -E "Major|Minor|Patch" $(VERSION_FILE) | grep -E "[0-9]+" -o | paste -sd "." -); \
	echo "New version: v$$NEW_VERSION"; \
	git add $(VERSION_FILE); \
	git commit -m "Bump version to v$$NEW_VERSION"; \
	git tag -a "v$$NEW_VERSION" -m "Release v$$NEW_VERSION"; \
	echo "Run 'git push && git push --tags' to publish"

.PHONY: release-minor
release-minor:
	@echo "Current version: v$(CURRENT_VERSION)"
	@CURRENT_MINOR=$$(grep "Minor = " $(VERSION_FILE) | grep -o "[0-9]*"); \
	NEW_MINOR=$$(expr $$CURRENT_MINOR + 1); \
	sed -i.bak "s/Minor = [0-9]*/Minor = $$NEW_MINOR/" $(VERSION_FILE); \
	sed -i.bak "s/Patch = [0-9]*/Patch = 0/" $(VERSION_FILE); \
	rm -f $(VERSION_FILE).bak; \
	NEW_VERSION=$$(grep -E "Major|Minor|Patch" $(VERSION_FILE) | grep -E "[0-9]+" -o | paste -sd "." -); \
	echo "New version: v$$NEW_VERSION"; \
	git add $(VERSION_FILE); \
	git commit -m "Bump version to v$$NEW_VERSION"; \
	git tag -a "v$$NEW_VERSION" -m "Release v$$NEW_VERSION"; \
	echo "Run 'git push && git push --tags' to publish"

.PHONY: release-major
release-major:
	@echo "Current version: v$(CURRENT_VERSION)"
	@CURRENT_MAJOR=$$(grep "Major = " $(VERSION_FILE) | grep -o "[0-9]*"); \
	NEW_MAJOR=$$(expr $$CURRENT_MAJOR + 1); \
	sed -i.bak "s/Major = [0-9]*/Major = $$NEW_MAJOR/" $(VERSION_FILE); \
	sed -i.bak "s/Minor = [0-9]*/Minor = 0/" $(VERSION_FILE); \
	sed -i.bak "s/Patch = [0-9]*/Patch = 0/" $(VERSION_FILE); \
	rm -f $(VERSION_FILE).bak; \
	NEW_VERSION=$$(grep -E "Major|Minor|Patch" $(VERSION_FILE) | grep -E "[0-9]+" -o | paste -sd "." -); \
	echo "New version: v$$NEW_VERSION"; \
	git add $(VERSION_FILE); \
	git commit -m "Bump version to v$$NEW_VERSION"; \
	git tag -a "v$$NEW_VERSION" -m "Release v$$NEW_VERSION"; \
	echo "Run 'git push && git push --tags' to publish"

# Help
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  build           - Build the project"
	@echo "  install         - Install the project"
	@echo "  dev             - Run in development mode"
	@echo "  test            - Run tests"
	@echo "  test-verbose    - Run tests with verbose output"
	@echo "  coverage        - Run tests with coverage"
	@echo "  fmt             - Format code"
	@echo "  vet             - Run go vet"
	@echo "  lint            - Run fmt and vet"
	@echo "  tidy            - Tidy go modules"
	@echo "  verify          - Verify go modules"
	@echo "  clean           - Clean build artifacts"
	@echo "  version         - Show current version"
	@echo "  release-patch   - Bump patch version and create tag"
	@echo "  release-minor   - Bump minor version and create tag"
	@echo "  release-major   - Bump major version and create tag"
	@echo "  help            - Show this help message"