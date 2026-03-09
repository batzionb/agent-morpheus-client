# parse-spdx-api Specification

## Purpose
TBD - created by archiving change add-parse-spdx-endpoint. Update Purpose after archive.
## Requirements
### Requirement: Parse SPDX endpoint
The system SHALL provide a REST endpoint at `POST /api/v1/products/parse-spdx` that accepts multipart form data containing a single SPDX JSON file. The endpoint SHALL parse the file using the same SPDX parser logic as upload-spdx (SpdxParsingService), validate required SPDX structure (DESCRIBES relationship, product package, packages array), and return the parse result as JSON. The response SHALL include productInfo (spdxId, name, version, cpe), components (supported components with OCI purl: spdxId, name, version, purl, image), and unsupportedComponents (spdxId, name, version, purl). The endpoint SHALL NOT require a vulnerability ID, SHALL NOT create a product, and SHALL NOT accept credentials. When the file is missing or invalid (not valid JSON or missing required SPDX structure), the endpoint SHALL return HTTP 400 (Bad Request) with a JSON object mapping field names to error messages, including `"file": "error message"` for the file validation failure.

#### Scenario: Successful parse returns parse result
- **WHEN** a client submits a multipart form to `/api/v1/products/parse-spdx` with a valid SPDX JSON file
- **THEN** the system parses the file using the SPDX parser
- **AND** returns HTTP 200 (OK)
- **AND** the response body is JSON containing productInfo (spdxId, name, version, cpe), components (array of supported component objects with spdxId, name, version, purl, image), and unsupportedComponents (array of objects with spdxId, name, version, purl)
- **AND** components SHALL contain only components whose purl starts with `pkg:oci/`; all other package-of components SHALL appear in unsupportedComponents

#### Scenario: Missing file returns 400 with field error
- **WHEN** a client submits a multipart form to `/api/v1/products/parse-spdx` without providing a file
- **THEN** the system returns HTTP 400 (Bad Request)
- **AND** the response body is a JSON object mapping field names to error messages
- **AND** the response includes `"file": "error message"` indicating the file is required or missing

#### Scenario: Invalid SPDX file returns 400 with file error
- **WHEN** a client submits a multipart form to `/api/v1/products/parse-spdx` with a file that is not valid JSON or is valid JSON but missing required SPDX structure (e.g. no DESCRIBES relationship, product package not found, product name missing)
- **THEN** the system returns HTTP 400 (Bad Request)
- **AND** the response body is a JSON object mapping field names to error messages
- **AND** the response includes `"file": "error message"` describing the validation or parse failure

