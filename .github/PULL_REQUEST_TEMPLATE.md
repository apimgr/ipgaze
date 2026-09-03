## Summary

<!-- What does this PR change? Why does it exist? -->

## Change Type

- [ ] Bug fix
- [ ] New feature (matches spec in `IDEA.md`)
- [ ] Refactor / code quality
- [ ] Documentation
- [ ] CI/CD / build system
- [ ] Security fix

## Test Evidence

<!-- Show that the change works. Paste relevant test output, build output, or curl examples. -->

## Docs and Config Updates

- [ ] `docs/` updated for any user/admin/API/config changes
- [ ] `IDEA.md` updated if features or data models changed
- [ ] `README.md` updated if usage or installation changed
- [ ] Swagger annotations updated for any route changes

## Breaking Changes

<!-- List any breaking changes to routes, config keys, CLI flags, or response schemas. "None" is a valid answer. -->

## Security and Privacy Impact

<!-- Any new network calls, data storage, auth changes, or credential handling? "None" is a valid answer. -->

## Checklist

- [ ] Code follows spec in `AI.md` and `IDEA.md` — no guessing or deviations
- [ ] `CGO_ENABLED=0` — no CGO, pure Go
- [ ] No TODO/FIXME/HACK comments left in committed code
- [ ] No stub functions, placeholder routes, or "coming soon" pages
- [ ] No hardcoded dev values (hostname, IP, ports)
- [ ] Passwords use Argon2id; tokens stored as SHA-256 hash
- [ ] Dockerfile is in `docker/Dockerfile`, not project root
- [ ] All 8 build platforms covered if binary changes were made
