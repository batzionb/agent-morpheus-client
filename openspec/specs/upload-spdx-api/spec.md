# upload-spdx-api Specification

## Purpose
SPDX product upload API. Exhort HTTP usage and triage JSON rules live in **`specs/exhort-integration/spec.md`**; this spec covers SPDX orchestration and outcomes.

## Requirements
### Requirement: SPDX File Upload Endpoint
`POST /api/v1/products/upload-spdx` SHALL accept multipart vulnerability ID + SPDX file with optional credentials. CVE SHALL match `^CVE-[0-9]{4}-[0-9]{4,19}$`. On success: validate SPDX structure, identify product via DESCRIBES, extract optional CPE from product `externalRefs` (`SECURITY` / `cpe22Type`) into `metadata.cpe`, validate/store optional credentials and inject credential ID into component reports, create product, start async processing, return HTTP 202 with product ID.

Field validation failures SHALL return HTTP 400 mapping `cveId` and/or `file` to messages. Invalid credentials → HTTP 400 with top-level `error`. Credential storage failure → HTTP 500 with `error`.

`sbomValidationIssues` entries SHALL include `code`, `configuredProperty`, and `expectedLabels` (resolved from backend config).

#### Scenario: Successful SPDX upload
- **WHEN** valid CVE, valid SPDX JSON, and optional CPE/credentials are submitted
- **THEN** HTTP 202 returns product ID, product is created (with or without `metadata.cpe`), credentials are stored and injected when provided, and async processing starts

#### Scenario: Field validation errors
- **WHEN** CVE, file, or SPDX structure is invalid (including multiple simultaneous failures)
- **THEN** HTTP 400 returns field-name-to-message mappings for each failed field

#### Scenario: Credential errors
- **WHEN** credentials are invalid or storage fails
- **THEN** HTTP 400 or 500 returns descriptive `error` per the rules above

### Requirement: Unsupported component handling
Supported components (PACKAGE_OF to product) SHALL have purl starting with `pkg:oci/`. Each unsupported component SHALL be added to product `excludedComponents` with `exclusionType` **error** and a message stating expected `pkg:oci/` vs actual/missing purl. Async processing runs for supported only. `submittedCount` = supported + unsupported total.

Zero supported components SHALL throw parse error; upload returns HTTP 400 with `"file": "At least one supported component is required. Supported components are packages with a PACKAGE_OF relationship to the product that have a purl (package URL) starting with pkg:oci. No such components were found."`

#### Scenario: Mixed supported and unsupported components
- **WHEN** SPDX has OCI and non-OCI (or missing purl) components
- **THEN** supported components process async; unsupported are recorded in `excludedComponents` with `submittedCount` reflecting all components

#### Scenario: No supported components
- **WHEN** no OCI PACKAGE_OF components exist
- **THEN** HTTP 400 returns the exact file error message above

### Requirement: Dependency analytics (Exhort) CVE gate

Apply **`exhort-integration`** for invocation and triage interpretation. SPDX multi-component flow:

**Health gate:** After product creation, run whole-product Exhort health probe once before any component enters Syft/Exhort/agent pipeline. Probe success → `dependencyTriageUnavailable` false; failure → true and skip all per-component Exhort calls (full agent analysis still proceeds).

**When triage on:** Before agent submit, call Exhort with Syft CycloneDX. CVE **not present** → add `excludedComponents` with `exclusionType` **dependency_not_present**, omit `error`, skip report creation. CVE **present** → create/save/submit report. Operational Exhort failure (non-2xx, transport, empty body, **`ExhortCveGateException`**) → proceed with analysis and set **`componentDependencyTriageFailed` true** on the report (see repository reports table specs).

#### Scenario: CVE triage outcomes when active
- **WHEN** triage is active and Exhort returns a reliable interpretation
- **THEN** CVE not present excludes the component without a report; CVE present proceeds to agent analysis
- **WHEN** triage is active and Exhort fails operationally
- **THEN** analysis proceeds with **`componentDependencyTriageFailed` true** and no exclusion solely for that failure

### Requirement: Exhort health probe before SPDX whole-product analysis
For async multi-component SPDX uploads, probe Exhort **once** after product creation and before pipeline entry, using configurable base URL (`quarkus.rest-client.exhort.url`). Do **not** use GET `/q/health/*` (often 404 on hosted Exhort).

Send **`POST /api/v5/analysis`** with **`Content-Type: application/vnd.cyclonedx+json`** and minimal CycloneDX 1.6 body aligned with `scripts/query-exhort-health.sh` (`health-probe` application). **Healthy** = HTTP 2xx within probe timeout; else **unhealthy**.

#### Scenario: Healthy probe enables triage
- **WHEN** probe succeeds
- **THEN** `dependencyTriageUnavailable` is false and per-component CVE gate applies

#### Scenario: Unhealthy probe bypasses triage
- **WHEN** probe fails (non-2xx or transport/timeout)
- **THEN** `dependencyTriageUnavailable` is true, no per-component Exhort calls run, reports omit or false **`componentDependencyTriageFailed`**, and full agent analysis proceeds without CVE-not-in-tree exclusion
