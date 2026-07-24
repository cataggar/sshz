# Findings, responsible disclosure, and release gating

## Contact placeholders

Before sending candidate materials to a reviewer, maintainers must fill these
placeholders in the private review agreement and candidate record:

```text
primary_private_security_contact: <PROJECT-SELECTED-CONTACT>
backup_private_security_contact: <PROJECT-SELECTED-CONTACT>
encrypted_reporting_method_or_portal: <PROJECT-SELECTED-PRIVATE-METHOD>
public_security_policy_url: <PROJECT-SELECTED-URL>
acknowledgement_target: <DURATION>
status_update_cadence: <DURATION>
emergency_contact_method: <PROJECT-SELECTED-METHOD>
disclosure_coordinator: <PROJECT-SELECTED-OWNER>
```

No private contact is assumed or invented by this package. Until maintainers
publish or directly provide a private method, do not place vulnerability
details, proofs of concept, credentials, crash dumps, or unredacted logs in a
public GitHub issue. A public issue may request private coordination without
technical detail, but is not the disclosure channel.

Maintainers must acknowledge receipt, limit access to people needed for triage,
preserve original evidence, agree on coordinated-disclosure timing, and tell
the reporter before publishing identifying credit or sensitive details.

## Required finding record

Use one stable record per distinct root cause. Every field is required; use
`unknown`, `none`, or `not applicable — reason` explicitly.

```text
finding_id: <REVIEW-ID-FNNN>
title: <SHORT-NON-SENSITIVE-TITLE>
reported_utc: <TIMESTAMP>
reporter_and_contact: <PRIVATE-RECORD>
candidate_commit_sha: <FULL-SHA>
affected_versions_or_commits: <RANGE>
affected_files_symbols_lines: <LOCATIONS>
feature_and_trust_boundary: <TRANSPORT|KEX/CRYPTO|AUTH|CHANNELS/FORWARDING|
  ZLIB|MEMORY|SIDE-CHANNEL|BUILD/DEPENDENCY|OTHER>
description_and_root_cause: <DETAIL>
preconditions_and_attacker: <DETAIL>
confidentiality_integrity_availability_impact: <DETAIL>
reproduction_steps: <PRIVATE-DETAIL-OR-ARTIFACT-REFERENCE>
reproduction_artifact_hashes: <HASHES>
severity: <CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL>
severity_rationale: <IMPACT/EXPLOITABILITY/SCOPE; OPTIONAL-CVSS-VECTOR>
confidence: <CONFIRMED|LIKELY|TENTATIVE>
maintainer_owner: <ASSIGNED-PERSON-OR-TEAM>
tracking_item: <PRIVATE-ADVISORY-OR-REDACTED-PUBLIC-ISSUE-URL>
disclosure_state: <PRIVATE|COORDINATED|PUBLIC>
disposition: <OPEN|FIX-PLANNED|FIXED-PENDING-RETEST|FIXED-VERIFIED|
  ACCEPTED-RISK|DUPLICATE|NOT-REPRODUCIBLE|OUT-OF-SCOPE>
disposition_rationale_and_approvers: <DETAIL>
target_candidate_or_release: <ID>
fix_commits: <FULL-SHAS-OR-NONE>
regression_tests: <TESTS-OR-NONE>
independent_retester: <PERSON-OR-ORGANIZATION-OTHER-THAN-FIX-AUTHOR>
retest_candidate_sha: <FULL-SHA-OR-PENDING>
retest_environment_and_commands: <EXACT-REFERENCE-OR-PENDING>
retest_artifact_hashes: <HASHES-OR-PENDING>
retest_result_and_utc: <PASS|FAIL|INCOMPLETE-AND-TIMESTAMP>
residual_risk: <DETAIL>
public_credit_and_advisory_plan: <AGREED-PLAN>
```

Severity is based on plausible impact and exploitability within the documented
attacker model:

- **Critical:** practical compromise of host/user private keys, unauthenticated
  remote code execution or equivalent process compromise, widespread
  authentication bypass, or similarly catastrophic impact.
- **High:** practical network confidentiality/integrity break, host
  impersonation, authorization bypass, cross-channel/cross-session access, or
  severe remotely triggerable availability impact under realistic conditions.
- **Medium:** meaningful security impact requiring substantial preconditions or
  having constrained scope.
- **Low:** defense-in-depth weakness with limited impact/exploitability.
- **Informational:** hardening, documentation, or evidence gap without a
  demonstrated vulnerability.

CVSS may supplement but cannot replace the written rationale. When uncertain,
use the higher plausible severity until triage resolves the uncertainty.

## Tracking and disposition rules

1. Keep initial technical detail in the private security item chosen in the
   contact record. Assign a stable finding ID immediately.
2. Create one tracking item per confirmed root cause. A parent advisory may
   group findings, but each finding keeps its owner, severity, disposition,
   fix, and retest fields.
3. Public issues must use the stable ID and a redacted description. Link the
   private record without copying exploit details. Never use labels or titles
   that prematurely expose an uncoordinated vulnerability.
4. Cross-link duplicates to the canonical finding. `NOT-REPRODUCIBLE` and
   `OUT-OF-SCOPE` require evidence and reviewer notification; neither is a way
   to suppress a disputed finding.
5. An owner is accountable for progress, not automatically the fix author or
   risk approver. Every open finding has one owner and target candidate.
6. Do not close a tracking item merely because code was merged. `FIXED` remains
   pending until the fix is on a re-pinned candidate and independent retest
   evidence is attached.
7. Publication and reporter credit follow the coordinated plan. Security fixes
   and release notes should provide enough information for users to assess
   exposure without publishing unnecessary weaponized detail.

## Accepted risk

Only an explicit `ACCEPTED-RISK` record counts as risk acceptance. It must add:

```text
risk_statement: <CAUSE/EVENT/IMPACT>
affected_scope: <VERSIONS/DEPLOYMENTS>
reason_fix_is_not_selected: <RATIONALE>
compensating_controls: <SPECIFIC/TESTABLE>
residual_likelihood_and_impact: <RATIONALE>
expiration_or_review_date: <DATE>
reopen_triggers: <DEPENDENCY/THREAT/CONFIGURATION/EVIDENCE CHANGES>
approvers: <NAMED PROJECT ROLES>
user_documentation_and_release_note: <LINKS>
```

The reviewer must be told of the proposed disposition and may record
disagreement. Acceptance does not mean the reviewer approved it. Critical and
high findings cannot be accepted to unblock a production release under this
package; they remain release-blocking until fixed and independently verified.
Medium/low acceptance does not clear unrelated production blockers.

## Independent retest

The retester must not be the person who authored the fix. Prefer the original
reviewer; if unavailable, record the independent person's qualifications and
why substitution was necessary. Retest evidence must include:

- finding ID, fixed full commit and new RC tag;
- exact environment/tool/dependency versions and commands;
- original reproducer run against the vulnerable candidate when safe, and
  against the fixed candidate;
- regression/negative tests and relevant wider suite results;
- raw logs, exit codes, seeds/corpus/reproducer hashes, timestamps, and evidence
  bundle digest; and
- a result of pass, fail, or incomplete plus residual-risk observations.

A maintainer assertion, code review approval, CI green check, or test written by
the fix author is useful evidence but is not independent retest evidence.
Retest against a branch, dirty tree, abbreviated SHA, or superseded candidate
does not clear the finding.

## Production release gate

A production release is blocked if any candidate-affecting critical/high
finding is:

- `OPEN`, `FIX-PLANNED`, `FIXED-PENDING-RETEST`, disputed without resolution,
  accepted risk, or missing an owner/tracking item;
- fixed only outside the pinned release commit;
- retested with a failure or incomplete result;
- retested only by the fix author or without reproducible evidence; or
- verified only on a superseded candidate after later relevant changes.

Before release, maintainers must query the complete private/public finding
index, not only open public issues, and sign a gate record containing the
candidate SHA, report/evidence digests, every critical/high ID and final
disposition, retest references, and remaining medium/low accepted risks.
Passing this finding gate does not clear the other blockers in the [production
threat model](../threat-model.md#production-release-blockers) or the
[algorithm-policy criteria](../algorithm-policy.md#production-release-criteria).
