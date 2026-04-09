# There's no standard format for reporting a software defect

We have formats for publishing vulnerabilities — CVE,
CSAF, OSV. We have formats for scan output — SARIF.
We have formats for SBOMs — CycloneDX, SPDX.

There is no standard for the bit in the middle: what a
researcher actually submits when they find a defect.

Most coordination platforms accept free text. The
researcher writes a description, hopes the triager
interprets it correctly, and waits. If the description
is ambiguous, triage stalls. If the evidence is
incomplete, it bounces back. If the format varies
between submissions, every intake is a one-off parsing
exercise.

This doesn't scale. Automated tooling is producing
defect reports faster than ever. The intake process
hasn't kept up.

---

## TEF — Triageable Evidence Format

TEF is a YAML-based format for structured vulnerability
evidence. It gives researchers a standard way to
describe software defects so that triage systems —
human or automated — can classify them without
ambiguity.

```yaml
defect:
  product: UserPortal
  vendor: acme-corp.com
  type: api
  cwe: 89
  versions: [2.3.0, 2.4.0]
  presence: behavioural_deterministic

evidence:
  - title: Confirm injection via time delay
    location:
      type: endpoint
      value: "GET /api/users?sort="
    given:
      - authenticated as "viewer" role
    when:
      - GET /api/users?sort=id;SELECT+pg_sleep(5)--
    then:
      - response delayed by 5 seconds
      - status code 200
    reproduction:
      commands:
        - "time curl -s -H 'Cookie: ...' 'https://...'"
      code: |
        // src/handlers/users.ts:47
        const query = `SELECT * FROM users ORDER BY ${req.query.sort}`;
```

Structured metadata at the top. Given/When/Then
evidence scenarios below. Location data says where the
defect lives. Reproduction block carries the actual
commands, code, output, and logs that prove it.

The format covers every target type — web, API, mobile,
desktop, embedded, OT/SCADA, cloud, network, supply
chain — and every defect manifestation pattern, from
static credentials in a firmware binary to
timing-dependent race conditions in payment APIs to
prompt injection in LLM-powered applications.

19 defect classes including a dedicated AI & Machine
Learning class covering prompt injection, training data
poisoning, model extraction, excessive agent permissions,
RAG corpus manipulation, adversarial inputs, and model
supply chain compromise. The traditional classes are
there too — injection, memory safety, crypto, access
control, business logic, all the configuration classes.
But AI defects are first-class, not bolted on.

## Why YAML with Given/When/Then

YAML because it's native to the security toolchain.
Nuclei templates, Ansible playbooks, GitHub Actions,
Kubernetes manifests — the people who find
vulnerabilities already think in YAML. No custom parser
needed. Any YAML reader works.

Given/When/Then because it maps directly onto how
defects are discovered and verified. There are
preconditions (Given), a trigger (When), and an
observed outcome (Then). This is true whether you're
describing a SQL injection, a heap overflow, an
unauthenticated PLC, or a symlinked temp file race.

The combination means a researcher can write it by
hand, a parser can extract structure without AI, and a
triage pipeline can classify it programmatically.

## What makes it different from free text

A TEF submission carries:

**Presence pattern** — how the defect manifests. Is it
static in a binary? Observable in configuration?
Behavioural but deterministic? Timing-dependent?
Inherited from a dependency? This tells the triage
system what kind of verification is needed before
anyone reads the description.

**Location** — not just "the product" but exactly where.
The endpoint, the function, the binary offset, the
network port, the config file. A triager opens the
submission and knows where to look.

**Reproduction** — the actual commands that were run,
the code that's vulnerable, the output that proves it.
Not a prose description of what happened. The raw
artefacts.

**Multiple evidence scenarios** — one finding, multiple
angles. Each scenario is independent evidence. A
submission with three scenarios showing the same defect
from different angles is stronger than one with a
single scenario.

## What's available now

**73 exemplary templates** covering every major defect
class across all target types. SQL injection in a web
API. DLL sideloading on Windows. TOCTOU race conditions.
JTAG debug access on production hardware. Dependency
confusion in CI/CD pipelines. Integer overflow in media
parsers. Each is a complete TEF document with location
and reproduction blocks.

**An interactive builder** that walks through target
selection, defect classification, and evidence
construction with progressive filtering — select a
target type and the bug classes narrow to what's
relevant. Select a bug class and the presence patterns
narrow. Override any suggestion when you know better.
Live YAML preview as you build.

**A guide** explaining when to use each of the eight
presence patterns, with practical examples.

All three are open to anyone, no account needed:

- Templates: theclearingroom.io/templates
- Builder: theclearingroom.io/templates/builder
- Guide: theclearingroom.io/templates/guide

## The spec is open

TEF is published under CC0 — public domain. Draft
specification 0.1. The format advances to 1.0 after
two independent implementations in production
vulnerability coordination workflows.

The spec, templates, and builder are developed by The
Clearing Room, an independent vulnerability disclosure
clearing house structured as a Charitable Incorporated
Organisation. But TEF itself is not tied to any
platform. Any coordination body, bug bounty programme,
CERT, or triage tool can adopt it.

Specification: github.com/[repo]/tef

## What we're looking for

Feedback from people who handle vulnerability intake:

- CERTs and coordination centres — does this fit your
  triage workflow?
- Bug bounty platforms — would structured intake
  reduce your triage time?
- Security tool vendors — would your scanner benefit
  from outputting TEF alongside SARIF?
- Researchers — does the Given/When/Then + location +
  reproduction model match how you actually document
  findings?

If you process vulnerability submissions at any scale,
we'd like to hear whether this format would make your
intake faster and more consistent.

theclearingroom.io/templates
