# Security policy

## Supported versions

sshz is pre-1.0 and has no production-supported release line.

| Version | Security support |
| --- | --- |
| Current `main` development state | Best-effort investigation and fixes; not production support |
| Published pre-1.0 releases or older commits | Unsupported unless a GitHub Security Advisory explicitly says otherwise |

The [release checklist](doc/release-checklist.md) and
[threat model](doc/threat-model.md) list evidence required before any supported
release. A maintainer-led review does not replace the still-missing independent
review.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting route:
[Report a vulnerability](https://github.com/cataggar/sshz/security/advisories/new).
Do not include vulnerability details, exploits, credentials, private keys,
crash dumps, or sensitive logs in a public issue.

Include affected revisions, impact, preconditions, reproduction steps, and
sanitized logs or test cases when available. Maintainers will make a
best-effort acknowledgement within seven days, restrict access during triage,
and provide updates when material status changes. These are targets, not
guarantees of a fix, severity, bounty, release, or disclosure date.

## Coordinated disclosure

Please allow reasonable time for confirmation, remediation, testing, and
distribution before public disclosure. Maintainers will coordinate scope,
credit, and timing with the reporter and will not publish identifying credit
without consent. If the report is out of scope, not reproducible, or cannot be
fixed promptly, maintainers will explain the disposition where practical.

Confirmed vulnerabilities may be published as GitHub Security Advisories after
coordination and after users have a reasonable opportunity to update.
Advisories will identify affected versions or commits, impact, mitigations,
fixed revisions when available, and appropriate reporter credit. Public issues
may track non-sensitive follow-up work but are not the private reporting route.
