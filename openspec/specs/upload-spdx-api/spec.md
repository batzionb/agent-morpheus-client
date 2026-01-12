# upload-spdx-api Specification

## Purpose
TBD - created by archiving change add-cpe-metadata-spdx. Update Purpose after archive.
## Requirements
### Requirement: SPDX File Upload Endpoint
The system SHALL provide a REST endpoint at `/api/v1/products/upload-spdx` that accepts multipart form data containing a vulnerability ID and an SPDX file. The endpoint SHALL parse the uploaded file, validate its structure, validate the vulnerability ID format using the official CVE regex pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`, extract product information including CPE metadata, create a product entry, and start async component processing. The endpoint SHALL extract CPE (Common Platform Enumeration) information from the product package's `externalRefs` array where `referenceCategory` is `SECURITY` and `referenceType` is `cpe22Type`, and store it in the product's `metadata` field with the key `cpe`. When validation fails, the endpoint SHALL return a structured error response mapping field names to error messages.

#### Scenario: Successful SPDX upload with CPE extraction
- **WHEN** a user submits a multipart form to `/api/v1/products/upload-spdx` with a valid vulnerability ID (matching the official CVE regex pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`) and a valid SPDX JSON file containing a product package with CPE information in externalRefs
- **THEN** the system validates the vulnerability ID matches the official CVE regex pattern
- **AND** parses the file as JSON
- **AND** validates that the file contains required SPDX structure (SPDXID, relationships, packages)
- **AND** identifies the product package via DESCRIBES relationship
- **AND** extracts CPE from the product package's externalRefs where `referenceCategory` is `SECURITY` and `referenceType` is `cpe22Type`
- **AND** creates a product entry with the CPE value stored in the `metadata` field with key `cpe`
- **AND** starts async processing for all components
- **AND** returns HTTP 202 (Accepted) with the product ID

#### Scenario: Successful SPDX upload without CPE
- **WHEN** a user submits a multipart form to `/api/v1/products/upload-spdx` with a valid vulnerability ID and a valid SPDX JSON file that does not contain CPE information in the product package's externalRefs
- **THEN** the system processes the upload as described in the successful upload scenario
- **AND** creates a product entry without the `cpe` key in metadata (or with `cpe` set to null)
- **AND** the product is accessible via the products API

#### Scenario: Invalid SPDX file rejection with field mapping
- **WHEN** a user submits a multipart form to `/api/v1/products/upload-spdx` with a file that is not valid JSON or missing required SPDX fields
- **THEN** the system returns HTTP 400 (Bad Request)
- **AND** the response body is a JSON object mapping field names to error messages
- **AND** the response includes `"file": "error message"` indicating the validation failure
- **AND** the error message clearly describes the validation failure

#### Scenario: Missing vulnerability ID rejection with field mapping
- **WHEN** a user submits a multipart form to `/api/v1/products/upload-spdx` without providing a vulnerability ID
- **THEN** the system returns HTTP 400 (Bad Request)
- **AND** the response body is a JSON object mapping field names to error messages
- **AND** the response includes `"cveId": "error message"` indicating the vulnerability ID is required
- **AND** the error message clearly describes that the vulnerability ID is required

#### Scenario: Invalid vulnerability ID format rejection with field mapping
- **WHEN** a user submits a multipart form to `/api/v1/products/upload-spdx` with a vulnerability ID that does not match the official CVE regex pattern `^CVE-[0-9]{4}-[0-9]{4,19}$`
- **THEN** the system returns HTTP 400 (Bad Request)
- **AND** the response body is a JSON object mapping field names to error messages
- **AND** the response includes `"cveId": "error message"` indicating the vulnerability ID format is invalid
- **AND** the error message clearly describes the format requirement

#### Scenario: Missing file rejection with field mapping
- **WHEN** a user submits a multipart form to `/api/v1/products/upload-spdx` without providing a file
- **THEN** the system returns HTTP 400 (Bad Request)
- **AND** the response body is a JSON object mapping field names to error messages
- **AND** the response includes `"file": "error message"` indicating the file is required
- **AND** the error message clearly describes that the file is required

#### Scenario: Multiple field validation errors
- **WHEN** a user submits a multipart form to `/api/v1/products/upload-spdx` with both an invalid vulnerability ID and an invalid file
- **THEN** the system returns HTTP 400 (Bad Request)
- **AND** the response body is a JSON object mapping field names to error messages
- **AND** the response includes both `"cveId": "error message"` and `"file": "error message"`
- **AND** each field maps to its specific validation error message

