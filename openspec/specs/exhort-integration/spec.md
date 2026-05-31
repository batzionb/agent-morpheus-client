# exhort-integration Specification

## Purpose
Normative Exhort API v5 integration: contract reference, analysis invocation, and CVE triage interpretation (`providers`, recursive issue walk, **`ExhortCveGateException`**).

**Related:** SPDX upload orchestration in **`specs/upload-spdx-api/spec.md`**.

## Requirements

### Requirement: Trustify Dependency Analytics (Exhort) API contract reference

The system SHALL treat the Exhort **HTTP API v5** contract per **`docs/reference/exhort-trustify-da-api-v5-openapi.yaml`** (snapshot); authoritative upstream is **[trustify-da-api-spec](https://github.com/guacsec/trustify-da-api-spec)**.

### Requirement: Exhort dependency analysis invocation

The system SHALL call **`POST /api/v5/analysis`** with **`Content-Type: application/vnd.cyclonedx+json`**, optional **`cves`** query (comma-separated), and configurable base URL (default **`https://exhort.stage.devshift.net`**, e.g. `quarkus.rest-client.exhort.url`).

#### Scenario: Per-component analysis uses CycloneDX and CVE filter
- **WHEN** the system performs per-component CVE triage against Exhort
- **THEN** it sends CycloneDX JSON to **`POST /api/v5/analysis`** with **`cves`** including the submitted CVE id

### Requirement: Exhort analysis response interpretation for CVE triage

For **2xx** bodies used for CVE triage, the root SHALL be a JSON object with non-empty **`providers`**. Every provider SHALL have **`status.ok` true** (JSON boolean). Interpretation SHALL receive the CycloneDX JSON sent to Exhort to derive main-module base PURLs from Syft components whose **`properties`** include **`syft:metadata:mainModule`** with **`value`** equal to component **`name`**.

**`status.warnings`** is acceptable when null, missing, `{}`, or `[]`. For a non-empty object, each key is a component PURL (base = query suffix stripped); keys matching a derived main-module base PURL are ignored; any other key throws **`ExhortCveGateException`**. A non-empty array or a value that is neither object nor array throws **`ExhortCveGateException`**.

CVE presence: recursively walk **`sources`** → **`dependencies`** → **`issues`** / **`transitive`**; match submitted id to issue **`id`** or **`cves`** (trimmed). Null/missing nodes contribute no matches; non-array **`dependencies`**, **`issues`**, or **`transitive`** where traversal requires an array throw **`ExhortCveGateException`**. On **`ExhortCveGateException`**, callers SHALL NOT classify the CVE as **not present** solely from that response (SPDX triage-failed path: **`upload-spdx-api`**).

#### Scenario: Walk determines present vs absent
- **WHEN** interpretation completes without **`ExhortCveGateException`**
- **THEN** triage concludes **present** if the walk matches the submitted id, otherwise **not present**

#### Scenario: Interpretation failure is not “CVE absent”
- **WHEN** interpretation throws **`ExhortCveGateException`**
- **THEN** callers apply the triage-failed path and do not treat the CVE as **not present** based on that response alone
