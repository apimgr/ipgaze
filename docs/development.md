# Development

Guide for contributing to **ipgaze**.

## Prerequisites

- Docker (required for Go builds and tests)
- Make
- Git

**Note:** Go is not required locally. The Makefile runs Go commands through
`casjaysdev/go:latest` with CGO disabled.

## Getting Started

### Clone Repository

```bash
git clone https://github.com/apimgr/ipgaze.git
cd ipgaze
```

### Build

```bash
# Quick development build to a project-scoped OS temp directory
make dev

# Build local-platform binaries with version metadata
make local

# Build for all platforms
make release
```

### Quick Development Build

```bash
make dev
```

This creates development binaries in a unique directory under the OS temp
directory. Run the service in Docker; do not execute the Go binary on the host.

### Run Tests

```bash
# Unit tests with coverage enforcement
make test
```

## Project Structure

```
ipgaze/
├── src/                    # Go source code
│   ├── main.go             # Entry point
│   ├── server/             # HTTP server (anonymous, public)
│   ├── config/             # Configuration (file-only, server.yml)
│   ├── geoip/              # GeoIP database manager
│   ├── scheduler/          # Built-in task scheduler
│   ├── blocklist/          # IP blocklist manager
│   └── tor/                # Tor hidden service manager
├── docker/                 # Docker files, compose files, and rootfs overlay
├── docs/                   # ReadTheDocs documentation
├── tests/                  # Test scripts
│   ├── run_tests.sh        # Test runner
│   ├── docker.sh           # Docker tests
│   └── incus.sh            # Incus container tests
└── .github/                # GitHub Actions
    └── workflows/          # CI/CD workflows
```

## Coding Standards

### Go Style

- Follow standard Go formatting (`gofmt`)
- Use intent-revealing names
- Comments above code (never inline)
- No generic package names (`utils`, `helpers`, `common`)

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Packages | lowercase, singular | `server`, `config` |
| Files | snake_case | `user_service.go` |
| Functions | PascalCase (exported) | `HandleRequest` |
| Variables | camelCase | `userCount` |
| Constants | PascalCase | `DefaultPort` |

### Error Handling

- Always check errors
- Return errors, don't panic
- Use descriptive error messages

```go
// Good
if err != nil {
    return fmt.Errorf("failed to open config: %w", err)
}

// Bad
if err != nil {
    panic(err)
}
```

## Building

### Build

```bash
make build
```

`make build` writes artifacts under `binaries/`. `make dev` writes quick
development binaries under the OS temporary directory.

### All Platforms

```bash
make release
```

Builds for 8 platforms:

- linux-amd64, linux-arm64
- darwin-amd64, darwin-arm64
- windows-amd64, windows-arm64
- freebsd-amd64, freebsd-arm64

### Docker Image

```bash
make docker
```

## Testing

### Unit Tests

```bash
make test
```

### Integration Tests

```bash
./tests/run_tests.sh
```

### Docker Tests

```bash
./tests/docker.sh
```

## Documentation

### Build Docs Locally

```bash
# Install dependencies
python -m pip install -r docs/requirements.txt

# Serve locally
mkdocs serve
```

Access at `http://localhost:8000`

### Documentation Files

- `docs/index.md` - Homepage
- `docs/installation.md` - Installation guide
- `docs/configuration.md` - Configuration reference
- `docs/api.md` - API documentation
- `docs/cli.md` - CLI reference
- `docs/admin.md` - Server administration (file-based)
- `docs/security.md` - Security model and reporting channels
- `docs/integrations.md` - API and protocol integrations
- `docs/development.md` - This file

## Git Workflow

### Branches

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready code |
| `feature/*` | New features |
| `fix/*` | Bug fixes |
| `release/*` | Release preparation |

### Commit Messages

Follow conventional commits:

```
feat: add reverse DNS lookup
fix: correct IPv6 parsing
docs: update API reference
refactor: simplify cache logic
test: add integration tests
```

### Pull Requests

1. Fork the repository
2. Create feature branch
3. Make changes
4. Run tests (`make test`)
5. Submit PR

## CI/CD

### Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `release.yml` | Tag push (v*) | Build releases, 8 platforms |
| `beta.yml` | Push to main | Beta builds |
| `daily.yml` | Schedule | Daily builds |
| `docker.yml` | Release | Docker images |
| `ci.yml` | Push and pull requests | Tests, lint, build, coverage, and security checks |
| `licenses.yml` | Dependency changes and scheduled runs | Dependency license checks |

### Release Process

1. Update version in code
2. Create tag: `git tag v1.0.0`
3. Push tag: `git push origin v1.0.0`
4. CI builds all artifacts
5. Release created automatically

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build for current platform |
| `make release` | Build for all platforms |
| `make test` | Run tests |
| `make dev` | Build quick development binaries in the OS temp directory |
| `make docker` | Build Docker image |
| `make clean` | Clean build artifacts |

## Dependencies

### Required

- `github.com/go-chi/chi/v5` - HTTP router
- `github.com/robfig/cron/v3` - Internal scheduler
- `github.com/oschwald/maxminddb-golang` - MMDB reader for ip-location-db databases (no API key required)
- `github.com/cretz/bine` - Tor hidden service (pure Go)

### Optional

- `github.com/graphql-go/graphql` - GraphQL API
- `github.com/prometheus/client_golang` - Prometheus metrics

## Troubleshooting

### Build Fails

```bash
# Clean and rebuild
make clean
make build
```

### Tests Fail

```bash
# Check Docker is running
docker ps

# Run the project test target with verbose output
make test
```

### Docker Issues

```bash
# Check that the Docker daemon is available
docker info
make docker
```

## Resources

- [Repository](https://github.com/apimgr/ipgaze)
- [Issues](https://github.com/apimgr/ipgaze/issues)
- [Swagger UI](https://ifcfg.us/server/docs/swagger)
- [GraphQL UI](https://ifcfg.us/server/docs/graphql)
