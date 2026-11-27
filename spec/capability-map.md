# MedAudit secure software engineering upgrade

Status: approved by the owner on 2026-11-27 with instructions to implement, strengthen the visual design, add engineering features, and push to main. Implemented; see docs/verification.json for verification.

Reviewed upstream commit: `d68792b` (`Initial commit`).

## Objective

Turn the existing hospital audit prototype into a convincing secure software
engineering demonstration: show the security decision, the supporting evidence,
and how requirements and tests establish that the decision works.

Assumptions: a student project, synthetic patient data, a local demonstration on
Windows, and no paid services. Keep FastAPI, SQLite, vanilla JavaScript, and the
existing two-service architecture. Preserve the audit format and key ratchet.

## Capability map

| Module id | Responsibility | Depends on |
|---|---|---|
| secure-foundation | Reproducible setup; untracked generated keys/data; safe runtime platform; boundary validation; regression checks for existing security controls | — |
| emergency-review | Auditor disposition of emergency-access grants with comments, reviewer, timestamp, and an audited history | secure-foundation |
| risk-monitoring | Deterministic findings for repeated failed logins, repeated access denials, and emergency-access activity; visible evidence and rule descriptions | secure-foundation |
| evidence-export | Authorized, audited JSON/CSV exports with filters, verification metadata, checkpoint references, and safe spreadsheet text | secure-foundation, emergency-review, risk-monitoring |
| guided-demo | Accessible auditor dashboard, scenario walkthrough, role/permission explanation, and an isolated tampering lab | evidence-export |
| engineering-evidence | Requirements, architecture/UML, STRIDE, risk register, ADRs, requirement-to-test mapping, CI, and presentation walkthrough | guided-demo |

Dependency direction: a module consumes only modules listed in its dependency
column. `engineering-evidence` collects the final evidence; its requirements,
threat model, and test design begin before implementation and evolve with each
module. It is not an application dependency.

Build order: secure-foundation → emergency-review → risk-monitoring →
evidence-export → guided-demo → engineering-evidence completion.

## Review decisions

### Secure foundation

- Stop distributing generated databases, audit state, account hashes, root keys,
  and Python bytecode in new checkouts. Generate fresh synthetic installs locally.
  Historical keys remain public even if files are removed in a later commit.
- Prefer a documented Linux container for the Windows demonstration initially;
  preserve existing POSIX locks and permission checks. Verify the actual container
  runtime before promising support. Native Windows locking/ACL support is a
  separate option requiring concurrency and permission tests.
- Validate real dates and trimmed strings; reject whitespace-only patient names
  and emergency reasons. Reject unexpected security-sensitive request fields.
- Check the auditor's login ordering so a failed console audit does not leave an
  authenticated session. Test audit failures on state-changing operations.
- Move JavaScript into same-origin static files and tighten script CSP. Choose
  the smallest safe session approach in the foundation specification; review
  cookie CSRF requirements if changing from bearer sessions.
- Record background verifier failures in sanitized operational status/logs.
- Separate and pin runtime/development dependencies after validating compatible
  versions; retain the existing functional and cryptographic tests.

### New demonstration features

1. **Emergency access review:** an auditor marks a grant reviewed or flagged and
   records a reason. The original grant stays unchanged. Review history remains
   verifiable; a failed review audit prevents the disposition from being saved.
2. **Security findings:** an auditor sees rule, time window, actor, severity,
   contributing event sequences, and an explanation. Findings describe activity
   requiring investigation; they do not claim that an attack is proven.
3. **Evidence export:** download a filtered report only after verification.
   Include scope, generation time, record count, verified head, and checkpoint
   context. Exclude credentials, key material, and clinical text. A metadata hash
   is a digest, not an independent signature or compliance certification.
4. **Guided demo:** a visible sequence explains normal access, denied access,
   emergency access, auditor review, checkpoint publication, tampering, detection,
   and export. Tampering uses a disposable dataset and an explicit local command;
   do not add a remote endpoint that alters the live audit log.

## Software engineering methods to demonstrate

| Method | Deliverable | Demonstration value |
|---|---|---|
| Requirements engineering | SRS with functional/nonfunctional requirement IDs, user stories, acceptance criteria, and abuse cases | Explain what was built and why |
| Iterative development | Small task backlog with implementation and verification checkpoints | Show an incremental SDLC rather than a last-minute code drop |
| Modeling | Use-case, component, sequence, and data-model diagrams in Mermaid | Explain actors, trust boundaries, and the audit-first request flow |
| Threat modeling | STRIDE table plus likelihood/impact risk register | Connect each threat to a control and a negative test |
| Design decisions | ADRs for service separation, key ownership, audit-first behavior, platform choice, and review persistence | Defend architectural tradeoffs during the viva |
| Verification and validation | Unit, API integration, security regression, and browser demo checks | Produce evidence for the security claims |
| Traceability | Requirement → threat → implementation → test → demo step matrix | Let an examiner follow a claim end to end |
| DevSecOps | CI for tests, static analysis, dependency advisories, and secret scanning | Demonstrate repeatable quality gates |
| Operational readiness | Setup guide, backup/checkpoint explanation, sanitized failure status, and limitations | Explain how failures are detected and handled |

Use selected, versioned OWASP ASVS requirements as a checklist, not a claim of
complete ASVS coverage or medical/legal certification.

## Scope acceptance targets

- A fresh documented install produces new keys and synthetic data and starts both
  services on the chosen supported runtime.
- Existing cryptographic, access-control, expiry, and fail-closed tests pass;
  added negative tests cover the changed boundaries.
- Only auditors can review grants, read findings, or export audit evidence.
- Tampered hospital logs block every new evidence-consuming endpoint; failure of
  console auditing blocks privileged review and export operations.
- Review state survives restart and cannot silently rewrite grant history.
- Risk findings are reproducible from their documented rules and source events.
- Reports respect filters and protect CSV consumers against formula injection.
- The complete demo is rehearsable in approximately 8–10 minutes with visible
  expected outcomes and a reset procedure for disposable demo data.
- Documents distinguish implemented, verified, and deferred controls. CI is
  configured and its execution status is reported honestly.

## Deferred

- Blockchain: existing authenticated checkpoints already address the rollback
  demonstration without a distributed network.
- AI diagnosis or automatic clinical decisions: unrelated to audit assurance.
- Machine learning anomaly scoring: a small synthetic dataset cannot establish
  useful accuracy; explainable deterministic rules suit this demonstration.
- Full EHR workflows, billing, appointments, and real patient integrations.
- Enterprise SSO/MFA, cloud KMS, managed database, and production deployment.
- Legal compliance certification or a claim of production readiness.

## Scope execution

The owner authorized implementation and publishing to main. Native Windows support
replaced the initially proposed container-first approach because this workspace has
no Docker or WSL runtime. No paid services or clinical decision features were added.
Detailed contracts, decisions, and acceptance conditions are in docs/ENGINEERING.md
and the runtime requirement catalogue. The report follows the supplied course templates.

## References

- [Current code review and verification limits](../docs/upgrade-review.md)
- [OWASP ASVS](https://asvs.owasp.org/)
- [Python fcntl platform availability](https://docs.python.org/3/library/fcntl.html)
