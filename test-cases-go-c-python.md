# Exploit IQ Agentic AI System - Test Cases Document

**Document Version:** 1.0
**Date:** 2026-03-15
**System Under Test:** ExploitIQ Client (Agent Morpheus Client)
**Base URL:** `<EXPLOIT_IQ_CLIENT_HOST>/api/v1`

---

## Table of Contents

1. [Application Scan - Container Image (CycloneDX SBOM)](#1-application-scan---container-image-cyclonedx-sbom)
2. [Application Scan - Git Repository Snapshot](#2-application-scan---git-repository-snapshot)
3. [Language-Specific Analysis Test Cases](#3-language-specific-analysis-test-cases)
   - 3.1 [Go (Git Repository)](#31-go-git-repository)
   - 3.2 [C (Container Image - CycloneDX SBOM)](#32-c-container-image---cyclonedx-sbom)
   - 3.3 [Python (Git Repository)](#33-python-git-repository)
4. [Product Scan Analysis (SPDX SBOM)](#4-product-scan-analysis---spdx-sbom)

---

## Prerequisites

- ExploitIQ Client is deployed and accessible via a web browser.
- The user has authenticated through the configured OIDC provider and holds an authorized role (`exploit-iq-view`, `exploit-iq-prodsec`, or `exploit-iq-admin`).
- The ExploitIQ backend (`agent-morpheus`) is reachable.
- MongoDB is running and connected.
- GitHub API token is configured (for repository language detection).
- Syft is installed and available (for SPDX product scan flows).
- The user has acknowledged the AI Usage Notice on first visit.

---

## 1. Application Scan - Container Image (CycloneDX SBOM)

This section covers the flow of uploading a CycloneDX SBOM generated from a container image and analyzing a specific CVE for exploitability.

### TC-IMG-001: Successful CycloneDX Upload and Analysis Submission

**Objective:** Verify that uploading a valid CycloneDX SBOM with a CVE ID through the UI creates a Product, generates a Report, and submits it for exploitability analysis.

**Preconditions:**
- A CycloneDX 1.6 JSON SBOM file generated from a container image via `syft <image> -o cyclonedx-json`.
- The SBOM contains `metadata.component.name` and source properties in `metadata.properties` array. Source location is extracted from keys (in priority order): `image.source-location`, `org.opencontainers.image.source`, or `syft:image:labels:io.openshift.build.source-location`. Commit ID is extracted from: `image.source.commit-id`, `org.opencontainers.image.revision`, or `syft:image:labels:io.openshift.build.commit.id`.

**Test Data:**
- CVE ID: `CVE-2023-44487`
- CycloneDX SBOM file: [`nmstate-rhel8-operator-sbom.json`](https://drive.google.com/drive/folders/1WkFomTQNynW7ttRlacukes-vodtIpfII?usp=drive_link)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the Home page | Browser loads `/` | Home page renders with "Request analysis", "View Reports", and "Learn more" cards, plus the Metrics card showing last 7 days stats |
| 2 | Click the **"Request analysis"** card | The **Request Analysis Modal** dialog opens | Modal displays with a ToggleGroup ("SBOM" / "Single Repository") with "SBOM" selected by default, "CVE ID" input, "SBOM file" drag-and-drop area, and "Private repository" toggle |
| 3 | Type `CVE-2023-44487` into the **"CVE ID"** text input | Field validates in real-time against pattern `CVE-YYYY-NNNN+` | Helper text shows: "Enter the CVE identifier to analyze (e.g. CVE-2024-50602)". No validation error displayed |
| 4 | Drag and drop `valid-sbom.json` onto the file upload area (or click **"Upload"** and select the file) | Frontend parses the JSON file and detects `bomFormat: "CycloneDX"` + `specVersion: "1.6"` | File name appears in the upload area. Format detected as CycloneDX 1.6. Helper text: "Supported formats: JSON SPDX 2.3 and JSON CycloneDX 1.6" |
| 5 | Click the **"Submit Analysis Request"** button | Button text changes to **"Submitting..."** and both Submit and Cancel buttons become disabled. Frontend sends `POST /api/v1/products/upload-cyclonedx` (multipart form: `file=@nmstate-rhel8-operator-sbom.json`, `cveId=CVE-2023-44487`) | Response: `200 OK`. Response body contains a Product object with `name=registry.redhat.io/openshift4/kubernetes-nmstate-rhel8-operator`, `version=sha256:a5ecbc...`, `cveId=CVE-2023-44487` and the first associated report ID |
| 6 | (Automatic navigation) | Frontend extracts `cveId` and `reportId` from the response and navigates to `/reports/component/CVE-2023-44487/{reportId}` | Browser redirects to the **CVE Repository Report** page |
| 7 | Observe the Repository Report page header | Frontend sends `GET /api/v1/reports/{reportId}` to load the report details | Page title shows: "CVE Repository Report: CVE-2023-44487 \| kubernetes-nmstate-rhel8-operator \| sha256:a5ecbc...". An AI warning alert displays: "Always review AI generated content prior to use." |
| 8 | Observe the **Details Card** on the report page | Frontend polls `GET /api/v1/reports/{reportId}` every 5 seconds while status is `queued`, `sent`, or `pending` | **Analysis State** label shows a sync icon with status `Queued` or `Sent`. **CVE** field shows `CVE-2023-44487`. **Repository** shows `https://github.com/openshift/kubernetes-nmstate`. **Commit ID** shows `444141e` (shortened, linked to the commit) |
| 9 | Wait for analysis to complete | Frontend auto-refresh detects status change to `completed` and stops polling | **Analysis State** label changes to green **Completed** with a check-circle icon. **Intel Reliability Score**, **CVSS Score**, **Reason**, and **Summary** fields populate with analysis results |
| 10 | Observe the **Checklist Card** (Analysis Q&A) | Frontend renders checklist items as expandable accordion sections | Each accordion item shows a question (input) and the AI-generated response in markdown format. All items are expanded by default |
| 11 | Click the **Download** dropdown button and select **"VEX"** | Frontend downloads VEX JSON | VEX download is enabled and a VEX document is generated for the analysis |

**Expected Outcome:** The user uploads a real CycloneDX SBOM (generated by Syft from the `kubernetes-nmstate-rhel8-operator` container image) through the modal. The system extracts `source-location` and `commit.id` from the SBOM's `syft:image:labels:*` metadata properties. The user is redirected to the report page and sees the analysis progress from queued to completed with full exploitability results, checklist Q&A referencing `.go` files, and a downloadable VEX document.

---

### TC-IMG-002: CycloneDX Upload with Invalid JSON

**Objective:** Verify the system rejects a malformed JSON file with a user-visible error.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal** from the Home page | Modal opens | Form fields displayed |
| 2 | Type `CVE-2023-44487` into the **"CVE ID"** field | Validates format | No error |
| 3 | Upload a file `invalid.json` containing `{ broken json }` | Frontend attempts to parse the file as JSON | Validation error appears below the file upload area: **"File is not valid JSON"** |
| 4 | Attempt to click **"Submit Analysis Request"** | Button remains disabled or submission is blocked due to validation error | No API call is made. The form cannot be submitted |

---

### TC-IMG-003: CycloneDX Upload with Missing Component Name

**Objective:** Verify validation enforces required `metadata.component.name`.

**Test Data:**
- SBOM file based on the `nmstate-rhel8-operator` SBOM but with `metadata.component.name` removed.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, enter a valid CVE ID, and upload the incomplete SBOM | Frontend detects CycloneDX format, file passes JSON parsing | File accepted for upload |
| 2 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-cyclonedx` | Response: `400 Bad Request` |
| 3 | Observe the error display | Frontend extracts the error message from the 400 response | A red **danger Alert** appears in the modal: "Error submitting analysis request" with details indicating missing component name |
| 4 | Navigate to **Reports** page via the sidebar | Frontend sends `GET /api/v1/products` | No new Product entry appears in the reports list |

---

### TC-IMG-004: CycloneDX Upload with Invalid CVE ID Format

**Objective:** Verify CVE ID format validation (`CVE-YYYY-NNNN+`) in the UI.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal** and type `INVALID-ID` into the **"CVE ID"** field | Client-side validation runs against regex `^CVE-[0-9]{4}-[0-9]{4,19}$` | Validation error appears: **"CVE ID format is invalid. Must match the official CVE pattern CVE-YYYY-NNNN+"** |
| 2 | Clear the field and type `CVE-2023` (incomplete) | Client-side validation runs | Same validation error displayed |
| 3 | Clear the field and leave it empty, then click elsewhere | Required field validation triggers | Validation error appears: **"Required"** |
| 4 | Attempt to click **"Submit Analysis Request"** with any invalid CVE | Form validation prevents submission | Button click has no effect; no API call is made |

---

### TC-IMG-005: CycloneDX Upload with Missing File

**Objective:** Verify the system rejects requests without an SBOM file attachment.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal** and enter a valid CVE ID `CVE-2023-44487` | CVE field validates successfully | No error on CVE field |
| 2 | Do **not** upload any file. Click **"Submit Analysis Request"** | Client-side validation checks required file field | Validation error appears below the file upload area: **"Required"**. No API call is made |

---

### TC-IMG-006: CycloneDX Upload - Product Created Without Version

**Objective:** Verify a Product is created successfully when the SBOM has a component name but no version.

**Test Data:**
- SBOM based on the `nmstate-rhel8-operator` SBOM but with `metadata.component.version` removed.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, enter `CVE-2023-44487`, and upload the version-less SBOM | Frontend detects CycloneDX format | File accepted |
| 2 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-cyclonedx` | Response: `200 OK`. Product created with `name=registry.redhat.io/openshift4/kubernetes-nmstate-rhel8-operator`, `version` is null or empty |
| 3 | Observe the automatic redirect to the Repository Report page | Frontend navigates to `/reports/component/CVE-2023-44487/{reportId}` | Page title shows: "CVE Repository Report: CVE-2023-44487 \| kubernetes-nmstate-rhel8-operator". No version is displayed in the header |
| 4 | Verify the report is being processed | Frontend polls report status | Analysis State shows `Queued` or `Sent` |

---

### TC-IMG-007: Analysis Result - CVE Exploitable

**Objective:** Verify correct UI display when the system determines a CVE is exploitable.

**Test Data:**
- CVE ID: `CVE-2024-51744` (golang-jwt `ParseWithClaims` error handling vulnerability)
- CycloneDX SBOM file: [`ose-agent-installer-orchestrator-sbom.json`](https://drive.google.com/drive/folders/1WkFomTQNynW7ttRlacukes-vodtIpfII?usp=drive_link) (generated via `syft registry.redhat.io/openshift4/ose-agent-installer-orchestrator-rhel9:v4.16.0-202501171434.p0.gab9e2ad.assembly.stream.el9 -o cyclonedx-json`)

> **Note:** CVE-2024-51744 affects `golang-jwt/jwt` versions prior to v4.5.1 and v5.2.1. The image contains `jwt/v4 v4.5.0` and `jwt v3.2.2`, both vulnerable. The `golang-jwt` library is vendored in the assisted-installer repository (46 files) and is used by client/auth libraries for API communication. The `ParseWithClaims` function's error handling vulnerability is reachable through the operator's JWT token validation code path.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, enter `CVE-2024-51744`, and upload the `ose-agent-installer-orchestrator-sbom.json` SBOM. Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-cyclonedx` and redirects | Report page loads with initial status `Queued` or `Sent` |
| 2 | Wait on the Repository Report page for analysis to complete | Frontend polls `GET /api/v1/reports/{reportId}` every 5 seconds | Analysis State transitions to **Completed** (green, check-circle icon) |
| 3 | Observe the **CVE** field in the Details Card | Frontend renders the exploitability status label next to the CVE ID | A red **"Vulnerable"** label is displayed — CVE-2024-51744 affects `golang-jwt/jwt/v4 v4.5.0` which is used by the operator's auth/client libraries for JWT token validation |
| 4 | Observe the **Reason** and **Summary** fields | Frontend renders justification and summary | Reason and Summary text explain why the CVE is exploitable (`ParseWithClaims` error handling vulnerability, affected code path reachable via JWT validation) |
| 5 | Click the **Download** dropdown and select **"VEX"** | Frontend downloads VEX JSON | VEX download is enabled and a VEX document is generated for the analysis |

---

### TC-IMG-008: Analysis Result - CVE Not Exploitable

**Objective:** Verify correct UI display when the CVE is present but not exploitable in the given context.

**Test Data:**
- CVE ID: `CVE-2024-44337` (infinite loop in `github.com/gomarkdown/markdown`)
- CycloneDX SBOM file: `nmstate-rhel8-operator-sbom.json` (same SBOM as TC-IMG-001). The `kubernetes-nmstate-rhel8-operator` does not use the `gomarkdown/markdown` library; the vulnerable code path is not reachable.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, enter `CVE-2024-44337`, and upload the `nmstate-rhel8-operator-sbom.json` SBOM. Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-cyclonedx` and redirects | Report page loads with initial `Queued` or `Sent` status |
| 2 | Wait for analysis to complete | Frontend polls report status | Analysis State transitions to **Completed** |
| 3 | Observe the **CVE** field in the Details Card | Frontend renders the exploitability status label | A green **"Not Vulnerable"** label is displayed — the vulnerable `gomarkdown/markdown` library is not used by the operator |
| 4 | Observe the **Reason** and **Summary** fields | Frontend renders justification details | Text explains why the CVE is not exploitable (vulnerable code path not reachable) |
| 5 | Click the **Download** dropdown and observe the **"VEX"** option | Frontend checks `report.output.vex` value | VEX download is **disabled** — VEX is only generated when the finding is Vulnerable |

---

### TC-IMG-009: Report Expiration on Timeout

**Objective:** Verify reports are displayed as expired after the configured timeout.

**Preconditions:**
- Set `morpheus.queue.timeout` to a short duration for testing (e.g., `10s`).

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Submit a report via the Request Analysis Modal | Frontend sends upload and redirects to the report page | Report page loads with **Queued** or **Sent** status |
| 2 | Wait on the report page beyond the configured timeout | Frontend polls `GET /api/v1/reports/{reportId}` and detects status change to `expired` | Analysis State transitions to grey **"Failed"** label with exclamation-circle icon |
| 3 | Observe the Details Card | Frontend stops polling once status is terminal | Failure reason displays: **"timeout after 10 seconds"** |

---

## 2. Application Scan - Git Repository Snapshot

This section covers the flow of directly analyzing a specific git repository commit for CVE exploitability. The user initiates this flow by selecting the **"Single Repository"** mode in the Request Analysis Modal, then entering a source repository URL and commit ID. The system creates a Report (no Product) and performs source-level analysis on the specified commit.

### TC-REPO-001: Successful Repository Analysis Submission

**Objective:** Verify that a report can be created and submitted for a git repository snapshot with a specified commit through the UI using the "Single Repository" mode.

**Test Data:**
- CVE ID: `CVE-2024-44337`
- Source Repository URL: `https://github.com/openshift/kubernetes-metrics-server`
- Commit ID: `bcbf241cece8ef455be32a910f1570bae827b4a1`

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the Home page and click the **"Request analysis"** card | Request Analysis Modal opens | Modal displays with a ToggleGroup ("SBOM" / "Single Repository"), CVE ID input, and Private repository toggle |
| 2 | Select the **"Single Repository"** toggle | Modal switches to Single Repository mode | File upload area is hidden. **Source Repository** URL and **Commit ID** text input fields are displayed |
| 3 | Enter `CVE-2024-44337` in the **"CVE ID"** field | Client-side validation passes | No error displayed |
| 4 | Enter `https://github.com/openshift/kubernetes-metrics-server` in the **"Source Repository"** field and `bcbf241cece8ef455be32a910f1570bae827b4a1` in the **"Commit ID"** field | Client-side validation passes | No error displayed |
| 5 | Click **"Submit Analysis Request"** | Button changes to **"Submitting..."**. Frontend sends `POST /api/v1/reports/new` (JSON body with `analysisType: source`) | Response: `202 Accepted`. Report created |
| 6 | (Automatic navigation) | Frontend navigates to `/reports/component/CVE-2024-44337/{reportId}` | Repository Report page loads |
| 7 | Observe the **Details Card** | Frontend sends `GET /api/v1/reports/{reportId}` | **Repository** field shows `https://github.com/openshift/kubernetes-metrics-server` (as external link). **Commit ID** shows `bcbf241` (linked to the specific commit on GitHub) |
| 8 | Observe the Analysis State | Frontend polls every 5 seconds | Status shows `Queued` or `Sent` initially |
| 9 | Wait for analysis to complete | Frontend detects `completed` status and stops polling | Analysis State changes to **Completed**. CVE status label shows green **"Not Vulnerable"** with justification `code_not_reachable`. Intel Reliability Score, Reason, and Summary are populated |

**Expected Outcome:** The analysis completes successfully and shows a **Not Vulnerable** status. The Reason field displays a justification and the Analysis Q&A section is populated.

---

### TC-REPO-002: Repository Analysis with GitHub Language Auto-Detection

**Objective:** Verify the system queries GitHub API to automatically detect the repository's programming languages when analyzing a repository via Single Repository mode.

**Test Data:**
- CVE ID: `CVE-2024-1485`
- Source Repository URL: `https://github.com/openshift/console` (a repository with Go, TypeScript, Python, and Shell)
- Commit ID: `350e1eabfd7b20f7ad56032b5a080d0cad4bd835`

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle, enter `CVE-2024-1485`, Source Repository URL `https://github.com/openshift/console`, and Commit ID `350e1eabfd7b20f7ad56032b5a080d0cad4bd835` | Fields validate | No errors displayed |
| 2 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` (JSON body with `analysisType: source`) | Response: `202 Accepted` |
| 3 | (Automatic navigation to the Repository Report page) | Frontend navigates to `/reports/component/CVE-2024-1485/{reportId}` | Repository Report page loads with initial `Queued` or `Sent` status |
| 4 | Wait for analysis to complete on the report page | Frontend polls report status | Analysis State changes to green **Completed**. The Analysis Q&A accordion items are populated with questions and AI-generated responses |

---

### TC-REPO-003: Repository Analysis with Invalid Repository URL

**Objective:** Verify error handling when the source repository URL entered in Single Repository mode is unreachable or invalid.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle, enter a valid CVE ID, type `https://github.com/nonexistent/repo` in the **"Source Repository"** field, and enter a commit ID | Frontend sends request | Response: `200 OK`. Report is created |
| 2 | Observe the Repository Report page after redirect | Frontend polls report status | Report eventually shows Analysis State as red **"Failed"** with exclamation-triangle icon |
| 3 | Observe error details on the page | Frontend renders error information | Error message indicates the source repository is inaccessible |

---

### TC-REPO-004: Repository Analysis with Invalid Commit ID

**Objective:** Verify error handling when the commit ID entered in Single Repository mode does not exist in the repository.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle, enter a valid CVE ID, a valid Source Repository URL, and type `0000000000000000` in the **"Commit ID"** field. Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` | Report is created |
| 2 | Observe the Repository Report page | Frontend polls report status | Analysis State transitions to **Failed** with error indicating invalid commit |

---

### TC-REPO-005: Repository Analysis with Credentials (Private Repository)

**Objective:** Verify analysis of a private repository using credentials provided through the UI in Single Repository mode.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle, and enter a valid CVE ID | CVE field validates | No error |
| 2 | Enter the private repository URL in the **"Source Repository"** field and a valid commit hash in the **"Commit ID"** field | Fields validate | No error |
| 3 | Toggle the **"Private repository"** switch to ON | Additional credential fields appear: **"Authentication secret"** text input with helper text: "Provide an SSH private key or Personal Access Token to authenticate with the private repository." | Credential fields are visible |
| 4 | Paste a Personal Access Token into the **"Authentication secret"** field | Frontend auto-detects credential type | A teal label **"Personal access token detected"** appears. A **"Username"** field becomes visible |
| 5 | Enter the GitHub username in the **"Username"** field | Username field accepts input | No error |
| 6 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` with `credential` object in JSON body (`secretValue`, `userName`) | Response: `202 Accepted`. Credentials are encrypted and stored with TTL |
| 7 | Observe the Repository Report page | Frontend polls report status | Report completes without authentication errors. Analysis State reaches **Completed** |

---

### **TC-REPO-006: Repository Analysis with Credentials (Private Repository, SSH Key)**

**Objective:** Verify analysis of a private repository using an SSH private key pasted in the Request Analysis modal in **Single Repository** mode. Credential type is auto-detected as SSH; the UI must not require a GitHub username, and the backend must accept the key-only credential payload.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
| :---- | :---- | :---- | :---- |
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle, and enter a valid CVE ID | CVE field validates | No error |
| 2 | Enter the private repository **clone URL** in **"Source Repository"** (e.g. `git@github.com:org/private-repo.git` or HTTPS URL for the same repo) and a valid commit hash in **"Commit ID"** | Fields validate | No error |
| 3 | Toggle the **"Private repository"** switch to ON | Additional credential UI appears: **"Authentication secret"** (password-masked) with helper text: *"Provide an SSH private key or Personal Access Token to authenticate with the private repository."* and *"Accepts SSH private keys or Personal Access Tokens. Type will be auto-detected."* | Credential block is visible |
| 4 | Paste a valid **SSH private key** into **"Authentication secret"** (PEM-style: begins with `-----BEGIN` and contains `-----END`) | Frontend auto-detects credential type as SSH | A **purple** label **"SSH key detected"** appears (with key icon). The **"Username"** field does **not** appear (unlike PAT mode) |
| 5 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` with `credential` in JSON body containing **`secretValue`** only (no `userName` for SSH) | Response: **202 Accepted**. Credential is encrypted and stored with TTL |
| 6 | Observe the Repository Report page | Frontend polls report status | Report completes without authentication errors. **Analysis State** reaches **Completed** |

**Negative / edge (optional):**

| Step | User Action (UI) | Expected Result |
| :---- | :---- | :---- |
| N1 | Private repo ON, empty **Authentication secret**, blur field | **"Required"** validation on authentication secret |
| N2 | PAT pasted first (teal label + Username shown), then replace secret with SSH key | Username field hides; only **SSH key detected** label remains; submit payload must not send stale `userName` for SSH |

---

### TC-REPO-007: Single Repositories Tab on Reports Page

**Objective:** Verify that reports submitted via Single Repository mode appear under the dedicated "Single Repositories" tab on the Reports page with the correct columns and filters.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the **Reports** page | Page loads with two tabs: **"SBOMs"** (default) and **"Single Repositories"** | "SBOMs" tab is active by default |
| 2 | Click the **"Single Repositories"** tab | Browser navigates to `/reports/single-repositories`. Frontend fetches single-repository reports | Table displays with columns: **ID**, **Repository**, **Commit ID**, **Finding**, **Date Requested**, **Date Completed** |
| 3 | Verify a report submitted via Single Repository mode appears in this tab | Report row is visible | Report shows the repository URL, commit ID, and current finding status |
| 4 | Verify the same report does **not** appear in the "SBOMs" tab | Switch back to "SBOMs" tab | The single-repository report is absent from the SBOMs table |
| 5 | Use the **"Finding"** filter dropdown | Filter options display: In progress, Failed, Vulnerable, Not vulnerable, Uncertain | Selecting a filter value narrows the table to matching reports |

---

### TC-REPO-008: Toggle Between SBOM and Single Repository Modes

**Objective:** Verify the Request Analysis Modal correctly switches between "SBOM" and "Single Repository" modes via the ToggleGroup.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal** | Modal opens with **"SBOM"** toggle selected by default | File upload area is displayed. Source Repository and Commit ID fields are hidden |
| 2 | Click the **"Single Repository"** toggle | Modal switches to Single Repository mode | File upload area is hidden. **Source Repository** URL and **Commit ID** text input fields are displayed |
| 3 | Click the **"SBOM"** toggle | Modal switches back to SBOM mode | File upload area reappears. Source Repository and Commit ID fields are hidden |
| 4 | In Single Repository mode, trigger a validation error (e.g., submit with empty fields), then switch to SBOM mode | Mode switches | Validation errors from Single Repository mode are cleared |
| 5 | In SBOM mode, submit a valid SBOM | Frontend sends `POST /api/v1/products/upload-cyclonedx` (multipart form) | Correct SBOM endpoint is called |
| 6 | In Single Repository mode, submit a valid repo URL and commit ID | Frontend sends `POST /api/v1/reports/new` (JSON body with `analysisType: source`) | Correct Single Repository endpoint is called |

---

### TC-REPO-009: Single Repository Analysis with Auto-Detected Ecosystem (Go)

**Objective:** Verify that submitting a Go repository in Single Repository mode results in the system auto-detecting the ecosystem and applying Go-specific language patterns for analysis.

**Test Data:**
- Source Repository URL: `https://github.com/openshift/openshift-controller-manager`
- Commit ID: `5dcfc990b109d9ae1d8b900655a928c6d859b584`
- CVE ID: `CVE-2024-45496`

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle | Modal switches to Single Repository mode | Source Repository and Commit ID fields are displayed |
| 2 | Enter `CVE-2024-45496` in the CVE ID field, `https://github.com/openshift/openshift-controller-manager` in the Source Repository field, and `5dcfc990b109d9ae1d8b900655a928c6d859b584` in the Commit ID field | Fields validate | No errors |
| 3 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` with JSON body | Response: `202 Accepted`. Report created |
| 4 | Wait for analysis to complete on the Repository Report page | Frontend polls report status | Analysis State shows **"Completed"**. CVE status label shows green **"Not Vulnerable"**. Reason field displays the justification (e.g. `code_not_reachable`). Analysis Q&A accordion is populated with checklist items |

**Expected Outcome:** The system auto-detects the Go ecosystem from the repository contents and completes the analysis. The report shows "Not Vulnerable" status and the Analysis Q&A section is populated.

---

### TC-REPO-010: CVE ID Regex Filtering on Single Repositories Tab

**Objective:** Verify that the CVE ID filter on the Single Repositories tab supports regex-based matching (partial patterns), not just exact match.

**Preconditions:**
- Multiple single-repository reports exist with different CVE IDs (e.g., `CVE-2024-44337`, `CVE-2024-45496`, `CVE-2023-45288`).

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the **Reports** page and click the **"Single Repositories"** tab | Table loads with all single-repository reports | All reports visible |
| 2 | Enter `CVE-2024` in the **CVE ID** search/filter field | Frontend sends query with regex filter | Table narrows to show only reports with CVE IDs matching `CVE-2024` (e.g., `CVE-2024-44337`, `CVE-2024-45496`) |
| 3 | Clear the filter and enter the full CVE ID `CVE-2023-45288` | Frontend sends query with exact CVE ID | Table shows only the report for `CVE-2023-45288` |
| 4 | Clear the filter | Frontend re-queries without filter | All reports are shown again |

---

## 3. Language-Specific Analysis Test Cases

These test cases verify that the system correctly identifies and applies language-specific include/exclude file patterns during exploitability analysis. Each language is tested through an application scan: Go and Python use the **Single Repository** mode in the Request Analysis Modal, where the user enters a source repository URL and commit ID directly. C uses the **container image with CycloneDX SBOM** flow (as C applications typically rely on image-level SBOM generation for complete dependency identification).

---

### 3.1 Go (Git Repository)

#### TC-LANG-GO-001: Go Application CVE Exploitability Analysis via Git Repository

**Objective:** Verify correct Go file pattern application and exploitability analysis of a Go dependency CVE by entering a Go git repository URL and commit ID via Single Repository mode.

**Test Data:**
- Source Repository URL: `https://github.com/openshift/kubernetes-metrics-server`
- Commit ID: `bcbf241cece8ef455be32a910f1570bae827b4a1`
- CVE ID: `CVE-2024-44337` (infinite loop in `github.com/gomarkdown/markdown`)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the Home page and click the **"Request analysis"** card | Request Analysis Modal opens | Modal displays with a ToggleGroup ("SBOM" / "Single Repository"), CVE ID input, and Private repository toggle |
| 2 | Select the **"Single Repository"** toggle | Modal switches to Single Repository mode | **Source Repository** URL and **Commit ID** text input fields are displayed |
| 3 | Enter `CVE-2024-44337` in the **"CVE ID"** field | Client-side validation passes | No error displayed |
| 4 | Enter `https://github.com/openshift/kubernetes-metrics-server` in the **"Source Repository"** field and `bcbf241cece8ef455be32a910f1570bae827b4a1` in the **"Commit ID"** field | Client-side validation passes | No error displayed |
| 5 | Click **"Submit Analysis Request"** | Button changes to **"Submitting..."**. Frontend sends `POST /api/v1/reports/new` (JSON body with `analysisType: source`) | Response: `202 Accepted`. Report created |
| 6 | (Automatic navigation to the Repository Report page) | Frontend navigates to `/reports/component/CVE-2024-44337/{reportId}` | Page title: "CVE Repository Report: CVE-2024-44337 \| kubernetes-metrics-server \| ..." |
| 7 | Observe the **Details Card** | Frontend loads report via `GET /api/v1/reports/{reportId}` | **Repository** shows `https://github.com/openshift/kubernetes-metrics-server`. **Commit ID** shows `bcbf241` (linked). Analysis State: `Queued` or `Sent` |
| 8 | Wait for analysis to complete | Frontend polls every 5 seconds, detects `completed` | Analysis State changes to green **Completed** |
| 9 | Observe the **CVE** status label in the Details Card | Frontend renders exploitability label | Green **"Not Vulnerable"** label is displayed. Reason field shows a justification |
| 10 | Expand the **Checklist Card** accordion items | Frontend renders Q&A pairs as expandable accordion sections | Analysis Q&A accordion items display questions and AI-generated responses |
| 11 | Click the **Download** dropdown and select **"Report"** | Frontend downloads `report-CVE-2024-44337-{reportId}.json` | Full report JSON saved |

**Expected Outcome:** The analysis completes successfully and shows a **Not Vulnerable** status. The Reason field displays a justification and the Analysis Q&A section is populated.

---

#### TC-LANG-GO-002: Go Repository - CVE Exploitable

**Objective:** Verify correct UI display when a Go CVE is determined to be exploitable.

**Test Data:**
- Source Repository URL: `https://github.com/openshift/assisted-installer`
- Commit ID: `ab9e2ade2f45890033a140b314ef87e367317b51`
- CVE ID: `CVE-2024-51744` (golang-jwt `ParseWithClaims` error handling vulnerability)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle, enter `CVE-2024-51744`, Source Repository URL `https://github.com/openshift/assisted-installer`, and Commit ID `ab9e2ade2f45890033a140b314ef87e367317b51`. Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` and redirects | Report page loads |
| 2 | Wait for analysis to complete | Frontend polls until `completed` | Analysis State: **Completed** |
| 3 | Observe the **CVE** status label | Frontend renders label | Red **"Vulnerable"** label is displayed — CVE-2024-51744 affects `golang-jwt/jwt/v4 v4.5.0` which is vendored in the assisted-installer repository |
| 4 | Expand the **Analysis Q&A** accordion items | Frontend renders Q&A analysis | Analysis Q&A accordion items display questions and AI-generated responses |
| 5 | Click **Download** > **"VEX"** | Frontend downloads VEX JSON | VEX download is enabled and a VEX document is generated for the analysis |
| 6 | Click **Download** > **"Report"** | Frontend downloads report JSON | Full report JSON saved |

**Expected Outcome:** The analysis completes successfully and shows a **Vulnerable** status. The Reason field displays a justification and the Analysis Q&A section is populated.

---

### 3.2 C (Container Image - CycloneDX SBOM)

#### TC-LANG-C-001: C Application CVE Exploitability Analysis via Container Image

**Objective:** Verify correct C file pattern application and exploitability analysis of a C library CVE by uploading a CycloneDX SBOM generated from a container image containing a C application.

**Test Data:**
- CVE ID: `CVE-2025-1094`
- Image: `registry.redhat.io/rhel8/postgresql-13:1-196.1724180180`
- Source Repository: `https://github.com/postgres/postgres`
- Commit/Tag: `REL_13_14`
- CycloneDX SBOM file: [`postgresql-13.json`](https://drive.google.com/drive/folders/1WkFomTQNynW7ttRlacukes-vodtIpfII?usp=drive_link)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the Home page and click the **"Request analysis"** card | Request Analysis Modal opens | Modal displays with "SBOM" selected by default, CVE ID input, file upload area, and Private repository toggle |
| 2 | Enter `CVE-2025-1094` in the **"CVE ID"** field | Client-side validation passes | No error displayed |
| 3 | Upload `postgresql-13.json` by dragging it onto the file upload area or clicking **"Upload"** | Frontend parses the JSON file and detects `bomFormat: "CycloneDX"` + `specVersion: "1.6"` | File name `postgresql-13.json` appears in the upload area |
| 4 | Click **"Submit Analysis Request"** | Button changes to **"Submitting..."**. Frontend sends `POST /api/v1/products/upload-cyclonedx` (multipart form) | Response: `200 OK`. Report created |
| 5 | (Automatic navigation to Repository Report page) | Frontend navigates to `/reports/component/CVE-2025-1094/{reportId}` | Repository Report page loads |
| 6 | Observe the **Details Card** | Frontend renders report details | **Analysis State**: `Queued` or `Sent`. **CVE**: `CVE-2025-1094`. **Repository**: `https://github.com/postgres/postgres` (external link). **Commit ID**: `REL_13_14` |
| 7 | Wait for analysis to complete | Frontend polls every 5 seconds | Analysis State changes to green **Completed** |
| 8 | Observe the **CVE** status label in the Details Card | Frontend renders exploitability status | Red **"Vulnerable"** label is displayed. Reason field shows a justification |
| 9 | Expand the **Analysis Q&A** accordion items | Frontend renders Q&A analysis | Analysis Q&A accordion items display questions and AI-generated responses |
| 10 | Click **Download** > **"Report"** | Frontend downloads report JSON | Full report JSON saved |

**Expected Outcome:** The analysis completes successfully and shows a **Vulnerable** status. The Reason field displays a justification and the Analysis Q&A section is populated.

---

#### TC-LANG-C-002: C Container Image - CVE Not Exploitable

**Objective:** Verify correct UI display when a C library CVE is present in the image but the vulnerable function is not reachable.

**Test Data:**
- CVE ID: `CVE-2022-37434` (zlib heap-based buffer over-read in `inflateGetHeader`)
- Same `postgresql-13.json` CycloneDX SBOM as TC-LANG-C-001. The SBOM includes `zlib` as a dependency, but PostgreSQL does not call the vulnerable `inflateGetHeader` function — PostgreSQL uses zlib for compression but through a safe subset of the API.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Upload the CycloneDX SBOM via the Request Analysis Modal with `CVE-2022-37434` | Frontend sends upload request and redirects to the report page | Report page loads with initial `Queued`/`Sent` status |
| 2 | Wait for analysis to complete on the Repository Report page | Frontend polls until `completed` | Analysis State changes to green **Completed** |
| 3 | Observe the **CVE** status label | Frontend renders exploitability label | Green **"Not Vulnerable"** label displayed — the vulnerable `inflateGetHeader` function in zlib is not called by the PostgreSQL application |
| 4 | Observe the **Reason** field in the Details Card | Frontend renders justification | Text explains the vulnerable zlib function (`inflateGetHeader`) is not reachable in this application's code path |

---

#### TC-LANG-C-003: C Container Image - Multiple C Components

**Objective:** Verify correct handling when the CycloneDX SBOM contains multiple C library dependencies.

**Test Data:**
- Same `postgresql-13.json` SBOM as TC-LANG-C-001, which contains multiple C library dependencies (e.g., `glibc`, `openssl-libs`, `zlib`)
- CVE ID: `CVE-2022-37434` (zlib heap-based buffer over-read)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Upload the CycloneDX SBOM with multiple C components via the Request Analysis Modal with `CVE-2022-37434` | Frontend sends upload request | Response: `200 OK`. All C components included in the report |
| 2 | Navigate to the Repository Report page after redirect | Frontend loads report | Details Card shows all component context |
| 3 | Wait for analysis to complete | Frontend polls until `completed` | Analysis State: **Completed**. Analysis Q&A accordion items are populated |
| 4 | Observe the **Summary** field | Frontend renders analysis summary | Summary focuses on zlib usage within the application, not glibc or openssl |

---

### 3.3 Python (Git Repository)

#### TC-LANG-PY-001: Python Application CVE Exploitability Analysis via Git Repository

**Objective:** Verify correct Python file pattern application and exploitability analysis of a Python dependency CVE by entering a Python git repository URL and commit ID via Single Repository mode.

**Test Data:**
- Source Repository URL: `https://github.com/TamarW0/example-repo`
- Commit ID: `f0bf2e6cb4ae65c53fa1764db6302b73cd52c6c0`
- CVE ID: `CVE-2024-49767` (Werkzeug denial of service via large file uploads)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the Home page and click the **"Request analysis"** card | Request Analysis Modal opens | Modal displays with a ToggleGroup ("SBOM" / "Single Repository"), CVE ID input, and Private repository toggle |
| 2 | Select the **"Single Repository"** toggle | Modal switches to Single Repository mode | **Source Repository** URL and **Commit ID** text input fields are displayed |
| 3 | Enter `CVE-2024-49767` in the **"CVE ID"** field | Client-side validation passes | No error |
| 4 | Enter `https://github.com/TamarW0/example-repo` in the **"Source Repository"** field and `f0bf2e6cb4ae65c53fa1764db6302b73cd52c6c0` in the **"Commit ID"** field | Client-side validation passes | No error |
| 5 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` (JSON body with `analysisType: source`) | Response: `202 Accepted`. Report created |
| 6 | (Automatic navigation to Repository Report page) | Frontend navigates to `/reports/component/CVE-2024-49767/{reportId}` | Page title: "CVE Repository Report: CVE-2024-49767 \| example-repo \| ..." |
| 7 | Observe the **Details Card** | Frontend loads report | **Repository**: `https://github.com/TamarW0/example-repo`. **Commit ID**: `f0bf2e6` (linked). Analysis State: `Queued` or `Sent` |
| 8 | Wait for analysis to complete | Frontend polls every 5 seconds | Analysis State: green **Completed** |
| 9 | Observe the **CVE** status label | Frontend renders exploitability label | Red **"Vulnerable"** label — the application uses the vulnerable Werkzeug file upload handling |
| 10 | Expand the **Checklist Card** accordion items | Frontend renders Q&A analysis | Analysis Q&A accordion items display questions and AI-generated responses |
| 11 | Click **Download** > **"Report"** | Frontend downloads full report JSON | Full report JSON saved |

**Expected Outcome:** The analysis completes successfully and shows a **Vulnerable** status. The Reason field displays a justification and the Analysis Q&A section is populated.

---

#### TC-LANG-PY-002: Python Repository - CVE Exploitable

**Objective:** Verify correct UI display when a Python CVE is determined to be exploitable.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle, enter `CVE-2024-49767`, Source Repository URL `https://github.com/TamarW0/example-repo`, and Commit ID `f0bf2e6cb4ae65c53fa1764db6302b73cd52c6c0`. Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` and redirects | Report page loads |
| 2 | Wait for analysis to complete | Frontend polls until `completed` | Analysis State: **Completed** |
| 3 | Observe the **CVE** status label | Frontend renders label | Red **"Vulnerable"** label |
| 4 | Click **Download** > **"VEX"** | Frontend downloads VEX JSON | VEX download is enabled and a VEX document is generated for the analysis |

---

#### TC-LANG-PY-003: Python Repository - CVE Not Exploitable

**Objective:** Verify correct UI display when a Python CVE is present in the dependency tree but the vulnerable code path is not reachable in the application.

**Test Data:**
- Source Repository URL: `https://github.com/TamarW0/example-repo`
- Commit ID: `f0bf2e6cb4ae65c53fa1764db6302b73cd52c6c0`
- CVE ID: `CVE-2023-30861` (Flask session cookie sent over HTTP without Secure flag)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, select **"Single Repository"** toggle, enter `CVE-2023-30861`, Source Repository URL `https://github.com/TamarW0/example-repo`, and Commit ID `f0bf2e6cb4ae65c53fa1764db6302b73cd52c6c0`. Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/reports/new` and redirects | Report page loads |
| 2 | Wait for analysis to complete | Frontend polls until `completed` | Analysis State: **Completed** |
| 3 | Observe the **CVE** status label | Frontend renders label | Green **"Not Vulnerable"** label with justification `requires_configuration` |
| 4 | Observe the **Reason** field in the Details Card | Frontend renders justification | Text explains the CVE is not exploitable because the Flask application does not set `session.permanent = True` (a necessary condition for exploitation) and additional cache control measures are in place |
| 5 | Expand the **Checklist Card** accordion items | Frontend renders Q&A analysis | Analysis Q&A accordion items display questions and AI-generated responses |

**Expected Outcome:** The analysis completes successfully and shows a **Not Vulnerable** status. The Reason field displays a justification and the Analysis Q&A section is populated.

---

## 4. Product Scan Analysis - SPDX SBOM

This section covers the flow of uploading an SPDX SBOM representing an entire product with multiple application components, and analyzing CVE exploitability across all of them.

### TC-PROD-001: Successful SPDX Upload with Multiple Components

**Objective:** Verify that uploading an SPDX SBOM through the UI creates a Product, generates individual Reports for each supported component, and submits them all for analysis.

**Preconditions:**
- An SPDX 2.3 JSON SBOM document describing a product with multiple OCI container image components.

**Test Data:**
- CVE ID: `CVE-2024-47561`
- SPDX SBOM file: [`gitops-1.19.spdx.json`](https://drive.google.com/file/d/1c1QmoZU-Kc205ZHvbmbr5Ff8ziPAg7_R/view?usp=drive_link)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the Home page and click the **"Request analysis"** card | Request Analysis Modal opens | Modal displays with a ToggleGroup ("SBOM" / "Single Repository") with "SBOM" selected by default, CVE ID input, file upload area, and Private repository toggle |
| 2 | Enter `CVE-2024-47561` in the **"CVE ID"** field | Client-side validation passes | No error |
| 3 | Upload `gitops-1.19.spdx.json` by dragging it onto the file upload area or clicking **"Upload"** | Frontend displays the filename in the file upload area | File accepted. Filename shown in upload field. (Note: SBOM format detection occurs on submit, not on upload — no format indicator is displayed at this step) |
| 4 | Click **"Submit Analysis Request"** | Button changes to **"Submitting..."**. Frontend sends `POST /api/v1/products/upload-spdx` (multipart form: `file=@gitops-1.19.spdx.json`, `vulnId=CVE-2024-47561`) | Response: `200 OK`. Product created with `name=gitops-1.19`, `version=` (empty), `submittedCount=3`, empty `submissionFailures` |
| 5 | (Automatic navigation) | Frontend extracts `productId` and `cveId` from the response and navigates to `/reports/product/{productId}/CVE-2024-47561` | Browser redirects to the **Report (Product)** page |
| 6 | Observe the **Report Details** card on the product page | Frontend sends `GET /api/v1/reports/product/{productId}` | **CVE Analyzed**: `CVE-2024-47561`. **Report name**: `gitops-1.19`. **Number of repositories analyzed**: `3 analyzed`. **Excluded components**: `0/3` (no link since count is 0) |
| 7 | Observe the **Component States** pie chart | Frontend renders distribution of analysis states | Chart shows states (e.g., 3 Queued or 3 Sent initially) |
| 8 | Observe the **CVE Status** pie chart | Frontend renders distribution of exploitability statuses | Chart shows pending results initially |
| 9 | Observe the **Repository Reports Table** | Frontend loads component reports | Table shows 3 rows (one per component): `gitops-operator-bundle-1-19`, `console-plugin-1-19`, `gitops-operator-1-19`. Each row shows Repository (external link), Commit ID, ExploitIQ Status, Completed date, Analysis state, and **"View"** button |
| 10 | Wait for component processing to complete | Frontend polls every 5 seconds while product state is incomplete | Component States pie chart updates as each component progresses through `Queued` → `Sent` → `Completed` |
| 11 | Wait for all three reports to complete | Frontend detects all components `completed` and stops polling | All three table rows show green **Completed** analysis state and exploitability status labels (**Vulnerable**, **Not Vulnerable**, or **Uncertain**) |
| 12 | Observe the **CVE Status** pie chart after completion | Frontend re-renders with final status counts | Pie chart shows final distribution (e.g., 1 Vulnerable, 1 Not Vulnerable, 1 Uncertain) |
| 13 | Click the **"View"** button on one of the component rows | Frontend navigates to `/reports/component/CVE-2024-47561/{reportId}` | Individual **CVE Repository Report** page loads with full analysis details, Checklist Q&A, and Download options |

**Expected Outcome:** The user uploads the real Red Hat `gitops-1.19` SPDX SBOM through the modal. The system parses the SPDX document, identifies the product via the `DESCRIBES` relationship, and discovers components via `PACKAGE_OF` relationships. Only `pkg:oci/` components are processed; each OCI component image is pulled and a CycloneDX SBOM is generated via Syft. The user is redirected to a product-level report page showing real-time progress as each component is processed and analyzed. The product summary aggregates exploitability results across all components.

---

### TC-PROD-002: SPDX Upload with Mixed Supported and Unsupported Components

**Objective:** Verify the system correctly handles SPDX SBOMs containing both OCI (supported) and non-OCI (unsupported) components, and shows excluded components in the UI.

**Test Data:**
- CVE ID: `CVE-2024-47561`
- SPDX SBOM file: [`gitops-1.19-with-unsupported-component.json`](https://drive.google.com/drive/folders/1WkFomTQNynW7ttRlacukes-vodtIpfII?usp=drive_link) (a modified version of the `gitops-1.19` SPDX) containing:
  - 2 OCI components (supported): `gitops-operator-bundle-1-19` (`pkg:oci/gitops-operator-bundle@sha256:5e78b9...`), `console-plugin-1-19` (`pkg:oci/console-plugin-rhel8@sha256:74112a...`)
  - 1 RPM component (unsupported): `dex-1-19` (`pkg:rpm/redhat/dex@2.39.1-3.el9?arch=x86_64`) — not OCI, so excluded from product scan

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, enter `CVE-2024-47561` in the CVE ID field, and upload `gitops-1.19-with-unsupported-component.json` | Frontend detects SPDX 2.3 format | File accepted |
| 2 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-spdx` | Response: `200 OK`. `submittedCount=2`, `submissionFailures` contains 1 entry (the RPM component `dex-1-19`) |
| 3 | Observe the **Report Details** card on the product page | Frontend loads product summary | **CVE Analyzed**: `CVE-2024-47561`. **Report name**: `gitops-1.19`. **Number of repositories analyzed**: `2 analyzed`. **Excluded components**: `1/3` (displayed as a clickable link) |
| 4 | Click the **"Excluded components"** link (`1/3`) | Frontend navigates to `/reports/product/excluded-components/{productId}/{cveId}` | **Excluded Components** page loads with breadcrumb: Reports > gitops-1.19/CVE-2024-47561 > Excluded components |
| 5 | Observe the Excluded Components table | Frontend renders `submissionFailures` data | Table shows 1 row: `dex-1-19` / `pkg:rpm/redhat/dex@2.39.1-3.el9?arch=x86_64` with error message about unsupported package type (only `pkg:oci` is supported) |
| 6 | Click the breadcrumb to return to the product report page | Frontend navigates back | Product page shows 2 component rows in the Repository Reports Table: `gitops-operator-bundle-1-19` and `console-plugin-1-19` |
| 7 | Verify the OCI components proceed to analysis | Frontend polls product status | Both OCI component reports reach **Completed** status |

---

### TC-PROD-003: SPDX Upload with No Supported Components

**Objective:** Verify proper error handling in the UI when all components in the SPDX SBOM are unsupported types.

**Test Data:**
- CVE ID: `CVE-2024-47561`
- SPDX SBOM file: [`gitops-1.19-no-supported-components.json`](https://drive.google.com/drive/folders/1WkFomTQNynW7ttRlacukes-vodtIpfII?usp=drive_link) (a modified version of the `gitops-1.19` SPDX) containing only non-OCI packages:
  - `gitops-operator-bundle-1-19` (`pkg:rpm/redhat/gitops-operator@1.19.0-8.el9?arch=x86_64`)
  - `console-plugin-1-19` (`pkg:rpm/redhat/console-plugin@1.19.0-8.el8?arch=x86_64`)
  - `dex-1-19` (`pkg:rpm/redhat/dex@2.39.1-3.el9?arch=x86_64`)
- The `SpdxParsingService` throws `SbomValidationException` when no `pkg:oci/` components are found.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, enter CVE ID, and upload the unsupported-only SPDX SBOM | Frontend detects SPDX 2.3 format | File accepted |
| 2 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-spdx` | Response: `400 Bad Request` |
| 3 | Observe the error display in the modal | Frontend extracts error from the 400 response | A red **danger Alert** appears: "Error submitting analysis request" with details indicating no supported components found |
| 4 | The modal remains open for correction | Submit button re-enables | User can upload a different file or cancel |

---

### TC-PROD-004: SPDX Upload with Missing DESCRIBES Relationship

**Objective:** Verify validation of the SPDX structure when the DESCRIBES relationship (identifying the product package) is missing.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Upload [`gitops-1.19-no-describes.json`](https://drive.google.com/drive/folders/1WkFomTQNynW7ttRlacukes-vodtIpfII?usp=drive_link) via the Request Analysis Modal | Frontend detects SPDX format | File accepted (JSON is valid) |
| 2 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-spdx` | Response: `400 Bad Request` |
| 3 | Observe the error display | Frontend renders error alert | Red **danger Alert** with message indicating product package not found (no DESCRIBES relationship) |

---

### TC-PROD-005: SPDX Upload with Missing Product Name

**Objective:** Verify validation when the DESCRIBES package has no name.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Upload [`gitops-1.19-product-no-name.json`](https://drive.google.com/drive/folders/1WkFomTQNynW7ttRlacukes-vodtIpfII?usp=drive_link) where the DESCRIBES package has an empty `name` field | Frontend accepts the file | JSON is valid |
| 2 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-spdx` | Response: `400 Bad Request` |
| 3 | Observe the error display | Frontend renders error alert | Error indicates product name is required |

---

### TC-PROD-006: SPDX Product Scan - Component Processing Failure for One Component

**Objective:** Verify that a processing failure for one component is displayed as an excluded component and does not block the remaining components.

**Preconditions:**
- One component image in the SPDX SBOM is invalid or unreachable (e.g., `pkg:oci/nonexistent-image@sha256:000`).

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Upload SPDX with 3 OCI components (one referencing a non-pullable image) via the Request Analysis Modal | Frontend sends upload request | Response: `200 OK` |
| 2 | Observe the product report page | Frontend loads product summary | **Number of repositories analyzed**: initially `3 analyzed` |
| 3 | Wait for component processing | Frontend polls product status | **Excluded components** count updates to `1/3` (clickable link) |
| 4 | Click the **"Excluded components"** link | Frontend navigates to Excluded Components page | Table shows 1 row with the failed component and an error message describing the failure |
| 5 | Return to the product report page | Frontend navigates back | Repository Reports Table shows 2 component rows proceeding through analysis |
| 6 | Wait for the remaining 2 components to complete | Frontend polls until all complete | Both remaining reports reach **Completed** status with exploitability results |

---

### TC-PROD-007: SPDX Product Scan - Component Syncer Timeout

**Objective:** Verify the UI displays expired reports when the Component Syncer does not respond within the configured timeout.

**Preconditions:**
- Set `morpheus.syncer.timeout` to a short value for testing (e.g., `10s`).

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Upload SPDX via the Request Analysis Modal | Frontend sends upload and redirects to product page | Reports created and sent to Component Syncer |
| 2 | Wait on the product report page beyond the syncer timeout | Frontend polls product status | Component States pie chart updates |
| 3 | Observe the Repository Reports Table rows | Frontend renders updated report statuses | Affected report rows show Analysis State: red **"Expired"** with exclamation-triangle icon |
| 4 | Observe the overall product Finding in the Reports listing page | Navigate to Reports page via sidebar | Product row shows **"Failed"** finding label (grey) indicating mixed/failed results |

---

### TC-PROD-008: Product Deletion Cascades to Reports

**Objective:** Verify that deleting a Product through the UI also removes all associated Reports.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Create a Product via SPDX upload with multiple components through the Request Analysis Modal | Frontend sends upload and redirects | Product and multiple Reports created |
| 2 | Navigate to the **Reports** page via sidebar | Frontend sends `GET /api/v1/products` with pagination | The new product appears in the Reports Table |
| 3 | Select the product row and trigger deletion (via delete action) | Frontend sends `DELETE /api/v1/products/{product_id}` | Response: `204 No Content` |
| 4 | Observe the Reports Table | Frontend refreshes the list | The deleted product no longer appears in the table |
| 5 | Navigate directly to `/reports/product/{product_id}/{cveId}` | Frontend sends `GET /api/v1/reports/product/{product_id}` | Response: `404 Not Found`. Page displays "Report not found" or redirects |

---

### TC-PROD-009: Product Summary Aggregation and Filtering

**Objective:** Verify the product summary correctly aggregates exploitability results across all components and supports filtering.

**Preconditions:**
- A completed product scan with 3 components:
  - Component A: CVE is exploitable (`TRUE`)
  - Component B: CVE is not exploitable (`FALSE`)
  - Component C: CVE status unknown (`UNKNOWN`)

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the completed product report page | Frontend sends `GET /api/v1/reports/product/{product_id}` | Product report page loads |
| 2 | Observe the **CVE Status** pie chart | Frontend renders `justificationStatusCounts` | Pie chart shows: 1 Vulnerable (red), 1 Not Vulnerable (green), 1 Uncertain (grey) |
| 3 | Observe the **Component States** pie chart | Frontend renders `statusCounts` | Pie chart shows: 3 Completed |
| 4 | In the **Repository Reports Table toolbar**, open the **ExploitIQ Status** filter dropdown and select **"Vulnerable"** | Frontend sends `GET /api/v1/reports?productId={id}&exploitIqStatus=TRUE` | Table filters to show only Component A (the vulnerable one) |
| 5 | Clear the ExploitIQ Status filter and select **"Not Vulnerable"** | Frontend re-queries with `exploitIqStatus=FALSE` | Table shows only Component B |
| 6 | Click **"Clear All Filters"** | Frontend removes all filters and re-queries | Table shows all 3 component rows |
| 7 | Click the **"View"** button on the Vulnerable component row | Frontend navigates to `/reports/component/CVE/{reportId}` | Individual report page loads with red **"Vulnerable"** label |
| 8 | Use the breadcrumb to navigate back to the product page | Frontend navigates to product report | Product page loads with aggregated view |

---

### TC-PROD-010: SPDX Upload - Queue Full Rejection

**Objective:** Verify the UI displays an error when the request queue is full.

**Preconditions:**
- Set `morpheus.queue.max-size=2` for testing.
- Already have 2 pending reports in the queue.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, enter CVE ID, and upload an SPDX SBOM | Frontend accepts the file | File and CVE validated |
| 2 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-spdx` | Response: `429 Too Many Requests` |
| 3 | Observe the error display in the modal | Frontend extracts error from the 429 response | A red **danger Alert** appears: "Error submitting analysis request" with details indicating queue capacity exceeded |
| 4 | Wait for existing reports to complete, then click **"Submit Analysis Request"** again | Frontend retries `POST /api/v1/products/upload-spdx` | Response: `200 OK`. Processing proceeds normally with redirect to product page |

---

### TC-PROD-011: SPDX Upload with Credentials for Private Registry

**Objective:** Verify that credentials provided through the UI during SPDX upload allow the system to process images from a private container registry.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Open the **Request Analysis Modal**, enter CVE ID, and upload an SPDX SBOM referencing private registry images | Frontend detects SPDX format | File accepted |
| 2 | Toggle the **"Private repository"** switch to ON | Credential fields appear | **"Authentication secret"** field and helper text visible |
| 3 | Paste a Personal Access Token into the **"Authentication secret"** field | Frontend auto-detects PAT | Teal **"Personal access token detected"** label. **"Username"** field appears |
| 4 | Enter the registry username | Username field accepts input | No error |
| 5 | Click **"Submit Analysis Request"** | Frontend sends `POST /api/v1/products/upload-spdx` with credentials | Response: `200 OK` |
| 6 | Observe the product report page | Frontend polls product status | Component processing proceeds. No authentication errors are displayed |
| 7 | Wait for all reports to complete | Frontend detects all reports `completed` | All component reports show **Completed** analysis state with exploitability results |

---

### TC-PROD-012: Product Report - Reports Page Listing

**Objective:** Verify product scan results are correctly displayed and filterable on the main Reports page.

**Preconditions:**
- Multiple product scans have been completed.

**Steps:**

| Step | User Action (UI) | Frontend Behavior (API) | Expected Result |
|------|-------------------|------------------------|-----------------|
| 1 | Navigate to the **Reports** page via the sidebar | Frontend sends `GET /api/v1/products` with default sorting (`submittedAt:DESC`) and pagination | Reports Table loads showing all products |
| 2 | Observe the table columns | Frontend renders product data | Each row shows: **Report ID** (clickable), **SBOM Name**, **CVE ID**, **Repos Analyzed** (e.g., "3 analyzed"), **Finding** (status label), **Submitted Date**, **Completion Date** |
| 3 | Type the product name in the **"Search by SBOM Name"** field | Frontend sends `GET /api/v1/products?sbomName=...` | Table filters to matching products |
| 4 | Clear the search and type a CVE ID in the **"Search by CVE ID"** field | Frontend sends `GET /api/v1/products?cveId=...` | Table filters to products analyzed for that CVE |
| 5 | Click the **"Submitted Date"** column header to sort ascending | Frontend sends `GET /api/v1/products?sortBy=submittedAt:ASC` | Table re-sorts with oldest first |
| 6 | Click a **Report ID** link in the table | Frontend navigates to `/reports/product/{productId}/{cveId}` | Product report page loads with aggregated view |

---

## Appendix A: Report Status State Machine

```
pending --> queued --> sent --> completed
   |          |         |
   v          v         v
 failed    failed    expired
              |
              v
           expired
```

- **pending**: Report created, not yet queued.
- **queued**: Report waiting for an active slot.
- **sent**: Report submitted to ExploitIQ backend.
- **completed**: Analysis finished, results available.
- **failed**: Processing error occurred (retryable).
- **expired**: Timeout exceeded without a response.

## Appendix B: Exploitability Status Values

| Value | UI Label | Color |
|-------|----------|-------|
| `TRUE` | **Vulnerable** | Red |
| `FALSE` | **Not Vulnerable** | Green |
| `UNKNOWN` | **Uncertain** | Grey |

## Appendix C: Supported PURL-to-Ecosystem Mapping

| PURL Type | Ecosystem (via `syft:package:type` property) | File Patterns (from `includes.json`) |
|-----------|----------------------------------------------|--------------------------------------|
| `pkg:golang/*` | go (mapped from `go-module`) | `**/*.go` |
| `pkg:rpm/*` (C libraries) | rpm (ecosystem detected via PURL type) | `**/*.c`, `**/*.h` |
| `pkg:pypi/*` | python | `**/*.py`, `pyproject.toml`, `setup.py`, `setup.cfg` |
| `pkg:npm/*` | javascript | `**/*.js`, `**/*.mjs`, `**/*.cjs`, `**/*.ts`, `**/*.tsx`, `tsconfig.json` |
| `pkg:maven/*` | java (mapped from `java-archive`) | `**/*.java`, `settings.gradle`, `src/main/**/*` |
| `pkg:oci/*` | (container) | Used in SPDX product scan for image identification (supported by `SpdxParsingService`) |

> **Note:** The ecosystem detection uses the `syft:package:type` component property first, then falls back to parsing the PURL type prefix. The `go-module` type is mapped to `golang`, and `java-archive` is mapped to `maven`. For SPDX product scans, only `pkg:oci/` PURLs are supported as component identifiers.

## Appendix D: UI Page Reference

| Page | Route | Purpose |
|------|-------|---------|
| Home | `/` | Dashboard with metrics, request analysis, view reports |
| Reports | `/reports` | Paginated product listing with search and filters |
| Product Report | `/reports/product/:productId/:cveId` | Multi-component product view with pie charts and component table |
| Excluded Components | `/reports/product/excluded-components/:productId/:cveId` | Lists components excluded from analysis |
| CVE Repository Report | `/reports/component/:cveId/:reportId` | Single component analysis details, checklist, downloads |
| CVE Details | `/reports/component/cve/:cveId/:reportId` | CVE metadata from NVD, GHSA, EPSS sources |

---

## Appendix E: Credential combinations (minimal)

Short matrix for **SBOM (SPDX / CycloneDX)** vs **Single Repository**, with **PAT** vs **SSH**. Duplicates point to existing cases above.

### TC-MATRIX-001: SPDX + PAT (private registry)

**Covered by:** TC-PROD-011 (section 4, SPDX upload with credentials).

---

### TC-MATRIX-002: SPDX + SSH (private registry)

**Objective:** SPDX upload with **SSH private key** (no username) for private OCI pulls.

| Step | User Action | Expected |
|------|-------------|----------|
| 1 | Request Analysis → **SBOM**, valid CVE, upload SPDX referencing private `pkg:oci/...` images; **Private repository** ON; paste PEM **SSH private key** | Purple **SSH key detected**; **Username** hidden |
| 2 | Submit | `POST /api/v1/products/upload-spdx` includes `secretValue` only → **200**; product page shows components progressing without registry auth errors |

---

### TC-MATRIX-003: CycloneDX + PAT (private registry)

**Objective:** CycloneDX product upload with PAT + username when the backend must authenticate to a private registry.

| Step | User Action | Expected |
|------|-------------|----------|
| 1 | Request Analysis → **SBOM**, CVE, upload CycloneDX JSON; **Private repository** ON; paste **PAT**; fill **Username** | Teal **Personal access token detected** |
| 2 | Submit | `POST /api/v1/products/upload-cyclonedx` multipart includes `secretValue` + `userName` → **200**; redirect to component report; analysis proceeds |

---

### TC-MATRIX-004: CycloneDX + SSH (private registry)

**Objective:** Same as TC-MATRIX-003 but credential is **SSH key** only.

| Step | User Action | Expected |
|------|-------------|----------|
| 1 | As TC-MATRIX-003 but paste **SSH private key** instead of PAT | Purple **SSH key detected**; no Username |
| 2 | Submit | `POST /api/v1/products/upload-cyclonedx` with `secretValue` only → **200**; no auth failures |

---

### TC-MATRIX-005: Single repository + PAT

**Covered by:** TC-REPO-005 (section 2).

---

### TC-MATRIX-006: Single repository + SSH

**Covered by:** TC-REPO-006 (section 2).
