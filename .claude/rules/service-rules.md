# Service Rules (PART 23, 24)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- Never run the service with more privilege than required — least-privilege runtime rules are non-negotiable
- Never silently drop privilege-escalation errors — fail secure

## CRITICAL - ALWAYS DO
- Support install/uninstall as a proper OS service (systemd/launchd/Windows service) per platform
- Verify service behavior with a real OS test (Incus `debian:latest` preferred) before reporting done

## Key Rules Summary
- **NOT YET FULLY POPULATED**: PARTs 23 (Privilege Escalation & Service) and 24 (Service Support) have not been read in this pass — only PART 0/1 general rules above are included. Read AI.md PART 23, 24 directly before doing service/daemon-specific work.

For complete details, see AI.md PART 23, PART 24.
