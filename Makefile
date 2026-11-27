# =============================================================================
# Makefile for ipgaze
# =============================================================================
# NEVER run Go or binaries locally - ALL builds use Docker containers
# =============================================================================

# PROJECT_NAME and PROJECT_ORG: IDEA.md project variables first, then git remote, then directory path.
PROJECT_NAME := $(strip $(shell sed -n 's/^project_name:[[:space:]]*//p' IDEA.md 2>/dev/null | head -n1))
ifeq ($(PROJECT_NAME),)
PROJECT_NAME := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)$$|\1|; s|\.git$$||' || basename "$$(pwd)")
endif
PROJECT_ORG := $(strip $(shell sed -n 's/^project_org:[[:space:]]*//p' IDEA.md 2>/dev/null | head -n1))
ifeq ($(PROJECT_ORG),)
PROJECT_ORG := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)/[^/]+(\.git)?$$|\1|' || basename "$$(dirname "$$(pwd)")")
endif

# INTERNAL_NAME is frozen at first-time setup (IDEA.md ## Project variables) - used for
# every on-disk identifier so a later PROJECT_NAME rename never orphans paths (PART 3)
INTERNAL_NAME := $(strip $(shell sed -n 's/^internal_name:[[:space:]]*//p' IDEA.md | head -n1))
ifeq ($(INTERNAL_NAME),)
$(error IDEA.md must define internal_name)
endif

# Local builds only: VERSION env (user override) > non-empty release.txt > short commit id > devel outside git
VERSION ?= $(shell v=; [ ! -r release.txt ] || v=$$(tr -d '[:space:]' < release.txt); if [ -n "$$v" ]; then echo "$$v"; else git rev-parse --short=7 HEAD 2>/dev/null || echo devel; fi)

# Build info - BUILD_EPOCH is the Unix timestamp injected via ldflags; the app
# derives the human-readable build date from it at runtime (never embed a
# pre-formatted date via ldflags - AI.md "Build Info Variables"). BUILD_DATE
# is derived from BUILD_EPOCH in ISO8601 UTC for Docker OCI labels only.
BUILD_EPOCH := $(shell date -u +%s)
BUILD_DATE := $(shell date -u -d @$(BUILD_EPOCH) +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -r $(BUILD_EPOCH) +"%Y-%m-%dT%H:%M:%SZ")
COMMIT_ID := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo "N/A")

# Official site URL (OPTIONAL - never guess or assume)
# Sources in order of precedence: site.txt > OFFICIAL_SITE env var > empty
OFFICIAL_SITE := $(shell [ -f site.txt ] && cat site.txt || echo "${OFFICIAL_SITE:-}")

# Linker flags to embed build info and strip debug symbols.
# -trimpath is a go build flag (not an ldflag) and is passed directly on each go build invocation below.
LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.CommitID=$(COMMIT_ID)' \
	-X 'main.BuildEpoch=$(BUILD_EPOCH)' \
	-X 'main.OfficialSite=$(OFFICIAL_SITE)'

# Directories
BINDIR := binaries
RELDIR := releases

# Absolute output directories live outside /app and must be mounted into the
# toolchain container. Relative directories are resolved under the /app mount.
ifneq ($(filter /%,$(BINDIR)),)
BUILD_BINDIR := $(BINDIR)
BUILD_OUTPUT_MOUNT := -v $(BINDIR):$(BINDIR)
else
BUILD_BINDIR := /app/$(BINDIR)
BUILD_OUTPUT_MOUNT :=
endif

# Build targets (8 platforms)
PLATFORMS ?= linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64,windows/arm64,freebsd/amd64,freebsd/arm64

# Docker - Set REGISTRY based on your platform (ghcr.io, registry.gitlab.com, git.example.com)
REGISTRY ?= ghcr.io/$(PROJECT_ORG)/$(PROJECT_NAME)

# Go cache directories (persistent across builds, bind-mounted into Docker)
GO_CACHE  ?= $(HOME)/go/pkg/mod
GO_BUILD  ?= $(HOME)/.cache/go-build/$(PROJECT_NAME)

# Resource limits for build containers
DOCKER_MEM  ?= 4g
DOCKER_CPUS ?= 2
DOCKER_CPU_SHARES ?= 256
DOCKER_TIMEOUT ?= 3600

# GO_DOCKER_RUN: shared docker run prefix (no image) so targets can add mounts before the image
GO_DOCKER_RUN := timeout -k 30 $(DOCKER_TIMEOUT) docker run --rm --no-healthcheck \
	--name $(PROJECT_NAME)-$$(tr -dc 'a-z0-9' </dev/urandom | head -c8) \
	--memory=$(DOCKER_MEM) --cpus=$(DOCKER_CPUS) --cpu-shares=$(DOCKER_CPU_SHARES) \
	$(BUILD_OUTPUT_MOUNT) \
	-v $(PWD):/app \
	-v $(GO_CACHE):/usr/local/share/go/pkg/mod \
	-v $(GO_BUILD):/usr/local/share/go/cache \
	-w /app \
	-e CGO_ENABLED=0 \
	-e GOFLAGS=-buildvcs=false
GO_DOCKER := $(GO_DOCKER_RUN) casjaysdev/go:latest
# CGO_ENABLED=0 and GOFLAGS=-buildvcs=false are casjaysdev/go:latest defaults; set explicitly for clarity

.PHONY: build local release release-check docker test dev clean

# =============================================================================
# BUILD - Build all platforms + local binary (via Docker with cached modules)
# =============================================================================
build: clean
	@mkdir -p $(BINDIR) $(GO_CACHE) $(GO_BUILD)
	@echo "Building version $(VERSION)..."
	@$(GO_DOCKER_RUN) -e BUILD_LDFLAGS="$(LDFLAGS)" casjaysdev/go:latest sh -c ' \
		set -e; \
		go mod tidy; \
		go mod download; \
		echo "Building $(PROJECT_NAME) (local platform)..."; \
		GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build -buildvcs=false -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BUILD_BINDIR)/$(PROJECT_NAME) ./src; \
		if [ -d src/client ]; then \
			echo "Building $(PROJECT_NAME)-cli (local platform)..."; \
			GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build -buildvcs=false -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BUILD_BINDIR)/$(PROJECT_NAME)-cli ./src/client; \
		fi; \
		for platform in $$(echo "$(PLATFORMS)" | tr "," " "); do \
			OS=$${platform%/*}; ARCH=$${platform#*/}; EXT=""; \
			if [ "$$OS" = "windows" ]; then EXT=".exe"; fi; \
			echo "Building server $$OS/$$ARCH..."; \
			GOOS=$$OS GOARCH=$$ARCH go build -buildvcs=false -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BUILD_BINDIR)/$(PROJECT_NAME)-$$OS-$$ARCH$$EXT ./src; \
			if [ -d src/client ]; then \
				echo "Building CLI $$OS/$$ARCH..."; \
				GOOS=$$OS GOARCH=$$ARCH go build -buildvcs=false -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BUILD_BINDIR)/$(PROJECT_NAME)-cli-$$OS-$$ARCH$$EXT ./src/client; \
			fi; \
		done'

	@test -s "$(BINDIR)/$(PROJECT_NAME)" || { echo "ERROR: missing local server binary" >&2; exit 1; }
	@if [ -d src/client ]; then test -s "$(BINDIR)/$(PROJECT_NAME)-cli" || { echo "ERROR: missing local CLI binary" >&2; exit 1; }; fi
	@for platform in $$(echo "$(PLATFORMS)" | tr "," " "); do \
		OS=$${platform%/*}; ARCH=$${platform#*/}; EXT=""; [ "$$OS" != windows ] || EXT=.exe; \
		test -s "$(BINDIR)/$(PROJECT_NAME)-$$OS-$$ARCH$$EXT" || { echo "ERROR: missing server binary for $$platform" >&2; exit 1; }; \
		if [ -d src/client ]; then test -s "$(BINDIR)/$(PROJECT_NAME)-cli-$$OS-$$ARCH$$EXT" || { echo "ERROR: missing CLI binary for $$platform" >&2; exit 1; }; fi; \
	done
	@echo "Build complete: $(BINDIR)/"

# =============================================================================
# LOCAL - Build local binaries only (fast development builds with version info)
# =============================================================================
local: clean
	@mkdir -p $(BINDIR) $(GO_CACHE) $(GO_BUILD)
	@echo "Building local binaries version $(VERSION)..."
	@$(GO_DOCKER_RUN) -e BUILD_LDFLAGS="$(LDFLAGS)" casjaysdev/go:latest sh -c ' \
		set -e; go mod tidy; go mod download; \
		echo "Building $(PROJECT_NAME)..."; \
		GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build -buildvcs=false -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BUILD_BINDIR)/$(PROJECT_NAME) ./src; \
		if [ -d src/client ]; then \
			echo "Building $(PROJECT_NAME)-cli..."; \
			GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build -buildvcs=false -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BUILD_BINDIR)/$(PROJECT_NAME)-cli ./src/client; \
		fi'

	@test -s "$(BINDIR)/$(PROJECT_NAME)" || { echo "ERROR: missing local server binary" >&2; exit 1; }
	@if [ -d src/client ]; then test -s "$(BINDIR)/$(PROJECT_NAME)-cli" || { echo "ERROR: missing local CLI binary" >&2; exit 1; }; fi
	@echo "Local build complete: $(BINDIR)/"

# =============================================================================
# DEV - Quick build for local development/testing (to random temp dir)
# =============================================================================
# Fast: local platform only, no ldflags, random temp dir for isolation
# Builds server + CLI (if they exist)
dev:
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@mkdir -p "$${TMPDIR:-/tmp}/$(PROJECT_ORG)" && \
		BUILD_DIR=$$(mktemp -d "$${TMPDIR:-/tmp}/$(PROJECT_ORG)/$(INTERNAL_NAME)-XXXXXX") && \
		echo "Quick dev build to $$BUILD_DIR..." && \
		$(GO_DOCKER_RUN) -v $$BUILD_DIR:/build casjaysdev/go:latest sh -c ' \
			set -e; go mod tidy; \
			GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build -buildvcs=false -o /build/$(PROJECT_NAME) ./src; \
			if [ -d src/client ]; then GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build -buildvcs=false -o /build/$(PROJECT_NAME)-cli ./src/client; fi' && \
		echo "Built: $$BUILD_DIR/$(PROJECT_NAME)" && \
		if [ -d "src/client" ]; then \
			echo "Built: $$BUILD_DIR/$(PROJECT_NAME)-cli"; \
		fi && \
		echo "Test:  docker run --rm --name $(PROJECT_NAME)-$$(tr -dc a-z0-9 </dev/urandom | head -c8) -v $$BUILD_DIR:/app alpine:latest /app/$(PROJECT_NAME) --help"

# =============================================================================
# RELEASE - Manual local release (stable only)
# =============================================================================
release-check:
	@echo "$(VERSION)" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' >/dev/null || { echo "ERROR: make release needs a stable SemVer X.Y.Z in release.txt (got '$(VERSION)')" >&2; exit 78; }

# beta publishes an immutable timestamp tag; CI builds and publishes its release.
beta:
	@[ "$$(git branch --show-current)" = main ] || { echo "beta: run it on main" >&2; exit 1; }
	@[ -z "$$(git status --porcelain)" ] || { echo "beta: the working tree is not clean" >&2; exit 1; }
	@TAG=$$(date -u +%Y%m%d%H%M%S)-beta; git tag "$$TAG" && git push origin "refs/tags/$$TAG" && echo "Pushed $$TAG"

release: release-check build
	@mkdir -p $(RELDIR)
	@echo "Preparing release $(VERSION)..."

	# Create version.txt
	@echo "$(VERSION)" > $(RELDIR)/version.txt

	# Copy binaries to releases (strip if needed)
	@for f in $(BINDIR)/$(PROJECT_NAME)-*; do \
		[ -f "$$f" ] || continue; \
		strip "$$f" 2>/dev/null || true; \
		cp "$$f" $(RELDIR)/; \
	done

	# Create source archive (exclude VCS and build artifacts)
	@tar --exclude='.git' --exclude='.github' --exclude='.gitea' \
		--exclude='binaries' --exclude='releases' --exclude='*.tar.gz' \
		-czf $(RELDIR)/$(PROJECT_NAME)-$(VERSION)-source.tar.gz .

	# Generate checksums
	@cd $(RELDIR) && FILES="$$(ls)" && sha256sum $$FILES > sha256.txt && sha512sum $$FILES > sha512.txt

	# Create the release without moving or deleting an existing tag.
	@gh release create v$(VERSION) $(RELDIR)/* \
		--title "v$(VERSION)" \
		--notes "Release v$(VERSION)" \
		--latest

	@echo "Release complete: v$(VERSION)"

# =============================================================================
# DOCKER - Build the host-platform container locally
# =============================================================================
# Uses multi-stage Dockerfile - Go compilation happens inside Docker
# No pre-built binaries needed
docker:
	@echo "Building Docker image $(VERSION)..."

	# Ensure buildx is available
	@docker buildx version > /dev/null 2>&1 || (echo "docker buildx required" && exit 1)

	# Create/use the ONE shared builder (never one per project: every builder is long-lived)
	@docker buildx create --name multiarch-builder --use 2>/dev/null || \
		docker buildx use multiarch-builder

	# Build the host platform locally; CI publishes multi-architecture images.
	@docker buildx build \
		-f docker/Dockerfile \
		--load \
		--build-arg VERSION="$(VERSION)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg COMMIT_ID="$(COMMIT_ID)" \
		--build-arg BUILD_EPOCH="$(BUILD_EPOCH)" \
		--build-arg OFFICIAL_SITE="$(OFFICIAL_SITE)" \
		-t $(REGISTRY):$(VERSION) \
		-t $(REGISTRY):latest \
		.
	@tests/image.sh $(REGISTRY):$(VERSION)

	@echo "Docker build complete: $(REGISTRY):$(VERSION)"

# =============================================================================
# TEST - Run Go checks and unit tests with coverage enforcement (via Docker)
# =============================================================================
# Coverage gate: >= 60% required. Binary integration tests live in tests/ and
# are run separately via tests/run_tests.sh — NOT as part of this target.
# Never skip with -short or -count=0. Coverage output goes to a tempdir under
test:
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@echo "Running tests with coverage..."
	@$(GO_DOCKER) sh -c " \
		TEST_ROOT= && \
		TEST_BASE=\"\$${TMPDIR:-/tmp}/$(PROJECT_ORG)\" && \
		cleanup() { \
			if [ -n \"\$$TEST_ROOT\" ] && [ -d \"\$$TEST_ROOT\" ] && [ ! -L \"\$$TEST_ROOT\" ]; then \
				case \"\$$TEST_ROOT\" in \"\$$TEST_BASE/$(INTERNAL_NAME)-\"*) rm -rf -- \"\$$TEST_ROOT\" ;; esac; \
			fi; \
		} && \
		trap cleanup EXIT && \
		mkdir -p \"\$$TEST_BASE\" && \
		TEST_ROOT=\$$(mktemp -d \"\$$TEST_BASE/$(INTERNAL_NAME)-XXXXXX\") && \
		export TMPDIR=\$$TEST_ROOT && \
		go mod download && \
		go test -v -cover -coverprofile=\$$TEST_ROOT/coverage.out ./... && \
		COVERAGE=\$$(go tool cover -func=\$$TEST_ROOT/coverage.out | grep total | awk '{print \$$3}' | sed 's/%//') && \
		echo \"Coverage: \$$COVERAGE%\" && \
		if [ \$$(echo \"\$$COVERAGE < 60\" | bc -l) -eq 1 ]; then \
			echo \"ERROR: Coverage is \$$COVERAGE%, must be >= 60%\"; exit 1; \
		fi && \
		echo \"Tests complete - Coverage: \$$COVERAGE% (>= 60% required) ✓\""

# =============================================================================
# CLEAN - Remove build artifacts
# =============================================================================
clean:
	@rm -rf $(BINDIR) $(RELDIR)
	@rm -f coverage.out coverage.html
