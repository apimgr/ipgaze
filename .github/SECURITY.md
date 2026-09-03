# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release (`stable`) | Yes |
| Beta builds | Best-effort |
| Older releases | No |

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.** Public disclosure before a fix is available puts all deployments at risk.

**To report a vulnerability:**

1. Email **apimgr@casjay.pro** with subject `[SECURITY] ipgaze — <short description>`
2. Include: affected version(s), reproduction steps, impact assessment, and any suggested fix
3. You will receive acknowledgment within 72 hours and a patch timeline within 7 days

**Alternative channels:**
- See [`/.well-known/security.txt`](https://ifcfg.us/.well-known/security.txt) for PGP key and additional contact options
- Use the `/server/contact` page on a running ipgaze instance with `security_id` parameter

## Disclosure Process

1. Maintainer acknowledges report within 72 hours
2. Maintainer confirms scope and severity
3. Fix developed and tested (private)
4. Fix released as a patch version
5. CVE requested if severity warrants it
6. Public disclosure after fix is available for at least 7 days

## Out of Scope

- GeoIP data accuracy (inherently approximate)
- Denial of service against a specific deployment (rate limits are the operator's responsibility)
- Missing features listed as non-goals in `IDEA.md`
