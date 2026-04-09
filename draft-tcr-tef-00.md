<!-- markdownlint-disable MD041 -->
---
title: "Triageable Evidence Format (TEF)"
abbrev: "TEF"
docname: draft-tcr-tef-00
category: info
ipr: trust200902

stand_alone: yes
smart_quotes: no
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

author
  -

    ins: J. Carroll
    name: John Carroll
    organization: The Clearing Room
    email: jc@thecontractor.io

normative:
  RFC2119:
  RFC8174:
  YAML:
    title: "YAML Ain't Markup Language Version 1.2"
    target: <https://yaml.org/spec/1.2.2/>

informative:
  CWE:
    title: "Common Weakness Enumeration"
    target: <https://cwe.mitre.org/>
  CVSS:
    title: "Common Vulnerability Scoring System"
    target: <https://www.first.org/cvss/>
  SARIF:
    title: "Static Analysis Results Interchange Format"
    target: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
  CSAF:
    title: "Common Security Advisory Framework"
    target: <https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html>
  OSV:
    title: "Open Source Vulnerability Format"
    target: <https://ossf.github.io/osv-schema/>
  ATLAS:
    title: "MITRE ATLAS"
    target: <https://atlas.mitre.org/>
  OWASPLLM:
    title: "OWASP Top 10 for LLM Applications"
    target: <https://owasp.org/www-project-top-10-for-large-language-model-applications/>

--- abstract

This document defines the Triageable Evidence Format
(TEF), a YAML-based format for structured vulnerability
evidence submission. TEF provides a standard way for
security researchers to describe software defects so
that triage systems — human or automated — can classify
them without ambiguity.

TEF combines YAML data structure with a Given/When/Then
evidence model. Each submission carries structured
metadata, one or more evidence scenarios with
preconditions, triggers, and observed outcomes, location
data identifying where the defect exists, and
reproduction artefacts proving its presence.

TEF is an intake format. It does not replace
vulnerability publication formats (CVE, CSAF, OSV) or
scan output formats (SARIF). It fills the gap between
discovery and classification — structuring what a
researcher submits so that coordination bodies,
triage pipelines, and verification teams can process
it consistently.

--- middle

Introduction
============

Vulnerability disclosure relies on structured formats
at the publication stage (CVE records, CSAF advisories,
OSV entries) and at the scanning stage (SARIF). There
is no equivalent standard for the intake stage — what
a researcher submits when reporting a software defect
to a coordination body, vendor, or disclosure platform.

Most intake systems accept free text. This creates
ambiguity, inconsistency, and friction. A researcher
describes their finding in prose. A triager interprets
the prose, potentially misunderstanding preconditions,
confusing the trigger with the outcome, or missing
evidence entirely. At scale, this process does not
work.

TEF addresses this gap by defining a structured,
machine-parseable, human-readable format for
vulnerability evidence.

Requirements Language
--------------------

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL",
"SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they
appear in all capitals, as shown here.

Format Overview
===============

A TEF document is a YAML file containing two required
top-level keys: `defect` and `evidence`.

The `defect` key contains structured metadata about the
affected product, vendor, target type, weakness
classification, affected versions, and defect
manifestation pattern.

The `evidence` key contains one or more scenarios, each
describing a distinct piece of evidence using a
Given/When/Then structure, an optional location block,
and an optional reproduction block.

Schema
======

Defect Block (REQUIRED)
-----------------------

The `defect` block MUST contain the following fields:

- `product` (string, REQUIRED): The name of the
  affected product.
- `vendor` (string, REQUIRED): The vendor domain or
  identifier.
- `type` (string, REQUIRED): The target type. See
  Section 4.
- `cwe` (integer, REQUIRED): The CWE identifier
  {{CWE}} for the weakness class.
- `versions` (array of strings, REQUIRED): The
  affected version range.
- `presence` (string, REQUIRED): The defect
  manifestation pattern. See Section 5.

The `defect` block MAY contain:

- `os` (string): The operating system or platform
  (e.g., "Windows 11", "Android 14", "Ubuntu 24.04").
- `description` (string): Freeform context.
- `cvss` (string): CVSS {{CVSS}} vector or score.
- `references` (array of strings): URLs, CVE IDs,
  advisory links.
- `reproduction_rate` (string): For probabilistic or
  timing-dependent defects (e.g., "15/100").
- `environment` (string): Specific environment if
  relevant.

Evidence Block (REQUIRED)
-------------------------

The `evidence` block MUST contain one or more scenario
entries. Each scenario MUST contain:

- `title` (string, REQUIRED): A short name for the
  scenario.
- `given` (array of strings, REQUIRED): Preconditions
  that must be true before the trigger.
- `when` (array of strings, REQUIRED): The action or
  input that reveals or triggers the defect.
- `then` (array of strings, REQUIRED): The observed
  outcome that proves the defect exists.

Each scenario MAY contain:

- `location`: A block identifying where the defect
  exists. See Section 6.
- `reproduction`: A block carrying proof artefacts.
  See Section 7.

Target Types
============

The `type` field in the `defect` block MUST be one of
the following values:

| Value | Description |
| ----- | ----------- |
| web | Web application |
| api | API or service endpoint |
| mobile_android | Android application |
| mobile_ios | iOS or iPadOS application |
| mobile | Mobile application (either platform) |
| desktop | Client-side desktop application |
| server | Server software |
| os | Operating system or kernel |
| embedded | Embedded system or firmware |
| network | Network device or infrastructure |
| cloud | Cloud service or SaaS platform |
| ot | OT, ICS, or SCADA system |
| ai_ml | AI/ML model or LLM-powered application |
| supply_chain | Third-party dependency or component |

Producers SHOULD use `mobile_android` or `mobile_ios`
rather than `mobile` when the defect is
platform-specific.

The `desktop` type refers to the application, not the
operating system. A Windows kernel vulnerability is
`os`, not `desktop`.

The `server` type covers software running as a service
(web servers, database servers, mail servers). Web
applications running on server software are `web`.

Presence Patterns
=================

The `presence` field in the `defect` block MUST be one
of the following values:

static_artefact
---------------

The defect exists in the artefact itself. It can be
confirmed by inspecting the binary, source, firmware,
configuration file, or package without executing the
software. Examples: hardcoded credentials, embedded
private keys, compiled-in backdoors.

static_config
-------------

The defect is observable in configuration settings,
HTTP response headers, DNS records, TLS handshake
parameters, or deployment policy. No exploitation is
needed to confirm it. Examples: missing security
headers, permissive CORS, weak TLS configuration.

behavioural_deterministic
-------------------------

The defect requires execution to observe, but the same
input always produces the same result. Reproduction is
reliable and repeatable in a single attempt. Examples:
SQL injection, path traversal, SSRF, IDOR.

behavioural_stateful
--------------------

The defect requires specific application state,
user roles, session conditions, or multi-step
interaction to trigger. Examples: privilege escalation,
business logic bypass, session fixation chains.

behavioural_timing
------------------

The defect depends on timing or concurrency. It may not
reproduce on every attempt. Submissions SHOULD include
`reproduction_rate`. Examples: race conditions, TOCTOU.

probabilistic
-------------

The same input may produce different outcomes across
runs because the system itself is non-deterministic.
This is distinct from `behavioural_timing` — the
variability is inherent to the system (model inference,
sampling-based algorithms), not to timing windows.
Submissions SHOULD include `reproduction_rate`.
Examples: prompt injection success rates, adversarial
input bypass rates.

environmental
-------------

The defect manifests only in specific deployment
environments, OS versions, hardware configurations, or
cloud regions. Submissions SHOULD include the
`environment` field and describe where the defect does
NOT reproduce for comparison. Examples: architecture-
specific buffer overflows, provider-specific cloud
metadata access.

design_flaw
-----------

The design itself is insecure. The software works as
designed — the design is the problem. No single code
fix resolves it without architectural change. Examples:
unsigned firmware updates, shared symmetric keys across
all devices.

supply_chain
------------

The defect is inherited from a third-party component
or dependency. Presence is confirmed by identifying
the dependency version and, where possible, verifying
reachability of the vulnerable code path. Examples:
known CVE in bundled library, dependency confusion.

Location Block
==============

The `location` block identifies where in the system the
defect exists. It MAY appear on any evidence scenario.

- `type` (string, REQUIRED): One of `endpoint`, `file`,
  `function`, `binary_offset`, `register`, `port`,
  `config`, `path`.
- `value` (string, REQUIRED): The specific location.
- `context` (string, OPTIONAL): Broader context.

Example:

    location:
      type: endpoint
      value: "GET /api/users?sort="
      context: behind nginx reverse proxy

Reproduction Block
==================

The `reproduction` block carries the raw proof
artefacts for a scenario. All fields are OPTIONAL.
Producers SHOULD include whichever fields are relevant.

- `commands` (array of strings): Exact commands
  executed.
- `code` (string): Vulnerable code snippet or exploit
  script.
- `request` (string): Raw protocol request.
- `response` (string): Raw protocol response.
- `logs` (string): Relevant log entries.
- `output` (string): Tool output, crash dumps,
  extraction results.
- `files` (array of objects): References to attached
  evidence files. Each object contains `name` (string),
  `hash` (string, SHA-256), and `type` (string).

File types: `script`, `pcap`, `har`, `sarif`, `binary`,
`config`, `screenshot`, `log`, `certificate`,
`core_dump`, `extraction`, `other`.

Defect Classes
==============

TEF recognises 19 defect classes across two categories.
The defect class is not a required field in the schema
but is RECOMMENDED for classification. Producers MAY
use the `bugClass` field in the `defect` block.

Code Defects
------------

injection, auth, crypto, data_exposure, access_control,
deserialization, file_handling, ssrf, memory, logic,
supply_chain, ai_ml

Configuration Defects
---------------------

config_tls, config_headers, config_secrets,
config_permissions, config_logging, config_dns,
config_default

The `ai_ml` class covers defects in AI and machine
learning systems including prompt injection, training
data poisoning, model extraction, adversarial inputs,
excessive agent permissions, RAG corpus manipulation,
and model supply chain compromise. This class maps to
{{OWASPLLM}} and {{ATLAS}}.

Conformance
===========

Producers
---------

A TEF producer is any system or person that generates
a TEF document. Producers MUST include all REQUIRED
fields. Producers SHOULD include location and
reproduction blocks where evidence is available.

Consumers
---------

A TEF consumer is any system that reads a TEF document.
Consumers MUST accept documents with unknown fields and
MUST NOT reject them. Consumers SHOULD implement both
schema validation (structure and types) and completeness
validation (evidence sufficiency).

Document Validity
-----------------

A TEF document is valid if:

1. It is valid YAML {{YAML}}.
2. The `defect` block contains all REQUIRED fields.
3. The `evidence` block contains at least one scenario.
4. Each scenario contains `title`, `given`, `when`, and
   `then`.
5. The `type` value is from Section 4.
6. The `presence` value is from Section 5.

Relationship to Other Formats
=============================

TEF is an intake format. It captures what a researcher
observed, structured for triage. After triage, findings
are published in other formats:

- CVE records for vulnerability identification
- CSAF {{CSAF}} advisories for vendor response
- OSV {{OSV}} entries for open source indexing
- SARIF {{SARIF}} for static analysis correlation

TEF does not duplicate these formats. It precedes them
in the vulnerability lifecycle.

Security Considerations
=======================

TEF documents may contain offensive security content:
exploit code, injection payloads, shell commands,
memory corruption details, and proof-of-concept
material. This is inherent to vulnerability evidence.
Systems processing TEF documents MUST treat all
user-supplied content (particularly `code`, `commands`,
`request`, and `output` fields) as untrusted input.

TEF documents SHOULD NOT contain plaintext credentials
or unredacted sensitive data belonging to third parties.
Producers SHOULD redact sensitive values where possible
while preserving enough information for verification.

The `reproduction` block may reference attached files
by SHA-256 hash. Consumers MUST NOT execute attached
files without explicit user authorisation.

IANA Considerations
===================

This document has no IANA actions.

A media type registration for `application/tef+yaml`
may be requested in a future version.

--- back

Acknowledgments
===============

The TEF format was developed through implementation
experience at The Clearing Room, an independent
vulnerability disclosure clearing house. Feedback from
the security research community, particularly on
presence pattern classification and AI/ML defect
coverage, shaped the current specification.

Examples
========

Complete TEF examples covering all target types and
presence patterns are maintained at the TEF template
library: <https://theclearingroom.io/templates>
