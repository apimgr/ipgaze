# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release (`stable`) | Yes |
| Beta builds | Best-effort |
| Older releases | No |

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.** Public disclosure before a fix is available puts all deployments at risk.

**For a vulnerability in the IPGaze repository:**

1. Use [GitHub Private Vulnerability Reporting](https://github.com/apimgr/ipgaze/security/advisories/new).
2. Include affected version(s), reproduction steps, impact, and any suggested fix.
3. Do not disclose the issue publicly before coordinating with the maintainers.

For a vulnerability in the official deployed service, use its current contact
channel from [`/.well-known/security.txt`](https://ifcfg.us/.well-known/security.txt).
That link opens the security-report form for the deployed instance. The
[disclosure policy](https://ifcfg.us/server/security/policy) covers the official
service and requests a 90-day coordinated-disclosure window.

## In Scope

- The IPGaze source code in this repository.
- The IPGaze service served from `https://ifcfg.us`, limited to IPGaze-owned
  functionality and data.

Testing other services, domains, or infrastructure hosted at the same provider
is outside this policy unless the affected service owner explicitly authorizes
it.

## Disclosure Process

1. Maintainers confirm scope and severity privately.
2. A fix is developed and tested before public disclosure when feasible.
3. Maintainers coordinate a reasonable disclosure date with the reporter, using
   the official service's 90-day policy as the default window.
4. A CVE may be requested when appropriate.

## Out of Scope

- GeoIP data accuracy (inherently approximate)
- Denial-of-service testing against the official deployment
- Missing features listed as non-goals in `IDEA.md`

## Safe Harbor

We consider security research conducted under this policy to be authorized.
If you make a good-faith effort to avoid privacy violations, service disruption,
and data access beyond what is needed to demonstrate the issue, we will not
recommend or pursue legal action for that research. Stop testing and report
promptly if you encounter personal data, credentials, or access to systems
outside the stated scope. This safe harbor applies only to IPGaze and cannot
bind third parties or waive their rights.
