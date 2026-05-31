# excluded-components-page Specification

## Purpose
Dedicated page listing product components excluded from analysis, with breadcrumbs and reason text derived from exclusion type.

## Requirements
### Requirement: Excluded components page route and layout
The application SHALL provide a page at `/reports/product/excluded-components/:productId/:cveId` with title "Excluded components" and subtitle "Components that were excluded from analysis due to technical errors or scope definitions".

#### Scenario: Excluded components page route
- **WHEN** a user navigates to `/reports/product/excluded-components/:productId/:cveId` with valid route parameters
- **THEN** the Excluded components page is displayed with the title and subtitle above

#### Scenario: Excluded components page breadcrumb
- **WHEN** a user views the Excluded components page
- **THEN** the breadcrumb shows "Reports" (link to `/reports`), `<product name> / <CVE ID>` (link to report page), and "Excluded components" (current page, non-clickable)
- **AND** product name comes from product API data; CVE ID from route parameters

### Requirement: Excluded components table
The page SHALL display a table with columns Component, Package URL, and Reason (no Exclusion type column), populated from `product.data.excludedComponents`. Each row SHALL show name and version, `image` as Package URL, and Reason from `exclusionType`: **dependency_not_present** → "Vulnerable package not in dependencies"; **error** → `excludedComponents[].error`. The `exclusionType` field SHALL exist on the API but not appear as its own column.

When validation failed because required CycloneDX source URL and/or commit ID metadata is missing, error text SHALL NOT be solely "SBOM metadata validation failed"; it SHALL state which metadata is missing (source URL, commit ID, or both), MAY include a Syft-specific prefix, and MAY list accepted `metadata.properties` names.

#### Scenario: Table displays excluded components
- **WHEN** the product has one or more `excludedComponents` entries
- **THEN** the table lists one row per entry with Component, Package URL, and Reason as above

#### Scenario: Missing image SBOM source metadata error is explicit
- **WHEN** an excluded row reflects CycloneDX image SBOM validation failure for missing source URL and/or commit metadata
- **THEN** the Reason text explicitly indicates what is missing
- **AND** the message is not solely "SBOM metadata validation failed"

#### Scenario: Table empty state
- **WHEN** `excludedComponents` is empty or undefined
- **THEN** the table displays an empty state message

#### Scenario: Page loading state
- **WHEN** product data is being fetched
- **THEN** a skeleton loading state is displayed until data is available
