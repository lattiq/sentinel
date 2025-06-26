VERSION_FILE := version.txt

# Read current version or default to v0.0.0
CURRENT_VERSION := $(shell cat $(VERSION_FILE) 2>/dev/null || echo "v0.0.0")

# Extract version numbers using cut instead of sed for simplicity
MAJOR := $(shell echo $(CURRENT_VERSION) | cut -d. -f1 | tr -d 'v')
MINOR := $(shell echo $(CURRENT_VERSION) | cut -d. -f2)
PATCH := $(shell echo $(CURRENT_VERSION) | cut -d. -f3)

.PHONY: version
version:
	@echo "Current version: $(CURRENT_VERSION)"

.PHONY: release-major
release-major:
	@echo "Current version: $(CURRENT_VERSION)"
	@NEW_VERSION="v$$(($(MAJOR) + 1)).0.0"; \
	echo "New version: $$NEW_VERSION"; \
	echo "$$NEW_VERSION" > $(VERSION_FILE); \
	git add $(VERSION_FILE); \
	git commit -m "Bump version to $$NEW_VERSION"; \
	git tag -a "$$NEW_VERSION" -m "Release $$NEW_VERSION"; \
	echo "Run 'git push && git push --tags' to publish"

.PHONY: release-minor
release-minor:
	@echo "Current version: $(CURRENT_VERSION)"
	@NEW_VERSION="v$(MAJOR).$$(($(MINOR) + 1)).0"; \
	echo "New version: $$NEW_VERSION"; \
	echo "$$NEW_VERSION" > $(VERSION_FILE); \
	git add $(VERSION_FILE); \
	git commit -m "Bump version to $$NEW_VERSION"; \
	git tag -a "$$NEW_VERSION" -m "Release $$NEW_VERSION"; \
	echo "Run 'git push && git push --tags' to publish"

.PHONY: release-patch
release-patch:
	@echo "Current version: $(CURRENT_VERSION)"
	@NEW_VERSION="v$(MAJOR).$(MINOR).$$(($(PATCH) + 1))"; \
	echo "New version: $$NEW_VERSION"; \
	echo "$$NEW_VERSION" > $(VERSION_FILE); \
	git add $(VERSION_FILE); \
	git commit -m "Bump version to $$NEW_VERSION"; \
	git tag -a "$$NEW_VERSION" -m "Release $$NEW_VERSION"; \
	echo "Run 'git push && git push --tags' to publish"

.PHONY: init-version
init-version:
	@if [ ! -f $(VERSION_FILE) ]; then \
		echo "v0.0.0" > $(VERSION_FILE); \
		git add $(VERSION_FILE); \
		git commit -m "Initialize version tracking"; \
		echo "Initialized version to v0.0.0"; \
	else \
		echo "Version file already exists with version: $$(cat $(VERSION_FILE))"; \
	fi