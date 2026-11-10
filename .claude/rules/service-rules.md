# Service Rules (PART 23, PART 24)

⚠️ **These rules are NON-NEGOTIABLE. Violations are bugs.** ⚠️

## CRITICAL - NEVER DO
- **PART 23:** Never prompts if user cannot escalate → shows informative error instead
- **PART 23:** *NEVER use these UIDs/GIDs even if they appear available on the current system.** These are commonly used by services across different distributions and may conflict if those services are installed later.

## CRITICAL - ALWAYS DO
- **PART 23:** | UID/GID | **Must match** - same value for both UID and GID |
- **PART 23:** *The UID and GID MUST be the same value.** Find an unused ID where both UID and GID are available AND not reserved by well-known services:
- **PART 23:** *Note:** Home directory must exist before user creation. Create directories first, then user, then set ownership.
- **PART 24:** *ALL projects MUST have built-in service support for ALL service managers.**
- **PART 24:** *Exception:** if IDEA.md explicitly requires permanent root, the service file and documentation MUST say so and explain why privilege drop is not possible.

## Key Rules Summary

### PART 23 — PRIVILEGE ESCALATION & SERVICE
- Overview
- Escalation Detection by OS
- Service Installation Logic
- Service Uninstall Logic
- Service Disable Logic
- Service Help Output
- Maintenance Help Output
- Shell Help Output
- Update Help Output
- System User Requirements

### PART 24 — SERVICE SUPPORT
- Built-in Service Support
- Service Templates

For complete details, see AI.md PART 23, PART 24.
