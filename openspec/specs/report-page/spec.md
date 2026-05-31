# report-page Specification

## Purpose
View SBOM report details: navigation, report and additional details cards, CVE status and component states donut charts, excluded components link, and repository reports table.

## Requirements
### Requirement: Report Page Navigation
The application SHALL provide navigation from the reports table to a report page when a user clicks the "SBOM Report ID" link in a table row. If `SbomReport.numReports === 1`, navigation SHALL go to `/reports/component/:cveId/:reportId` where `:cveId` is the CVE ID and `:reportId` is `SbomReport.firstReportId`. Otherwise, navigation SHALL go to `/reports/product/:productId/:cveId` where `:productId` is `SbomReport.productId` and `:cveId` is the CVE ID.

#### Scenario: Navigate to report page
- **WHEN** a user clicks the "SBOM Report ID" link in a table row
- **THEN** the application navigates to `/reports/component/:cveId/:reportId` when `numReports === 1`, or to `/reports/product/:productId/:cveId` otherwise

### Requirement: Report Details Display
The report page SHALL display report details in two separate cards positioned side by side at the top of the page using a `Grid` layout. The Details card (left) SHALL show report information in two columns; the right column SHALL display "Number of repositories analyzed" as `{num completed} / {num submitted}` (e.g. "5 / 10") using a shared formatter with no suffix, where num completed is `sbomReport.statusCounts["completed"]` (or 0 if absent) and num submitted is `product.data.submittedCount`. The Additional Details card (right) SHALL display a Completed date field and a Metadata field. Date fields SHALL use the format "DD Month YYYY, HH:MM:SS AM/PM" (e.g. "07 July 2025, 10:14:02 PM"), including day, full month name, year, time with seconds, and AM/PM. When no Date Completed is available, the Completed field SHALL show "-" or the `NotAvailable` component. When metadata exists in `product.data.metadata`, the Metadata field SHALL display all key-value pairs using PatternFly `LabelGroup` and `Label` components with format "key:value"; when metadata is empty or undefined, the Metadata field SHALL use the `NotAvailable` component. Displayed CVE data SHALL correspond to the CVE ID from route parameters.

The report page SHALL automatically refresh data using `useReport` with server live updates (`liveUpdatesRefresh`), but only when some analysis states in `sbomReport.statusCounts` are not "failed" or "completed". When all analysis states are either "failed" or "completed", live refetches SHALL stop while the shared live-updates `EventSource` remains open (see `api-hooks` and `report-events-stream` specifications).

The Details card SHALL display a field with label "Excluded components" and value `<numExcluded>/<numSubmitted>` where **numExcluded** is the length of `product.data.excludedComponents` (all exclusion types) and **numSubmitted** is `product.data.submittedCount`. When **numExcluded** > 0, the value SHALL be a link to `/reports/product/excluded-components/:productId/:cveId`. When **numExcluded** === 0, the value SHALL be `0/<numSubmitted>` as plain text (not a link).

#### Scenario: Report details cards display
- **WHEN** a user views the report page with a specific CVE ID in the route
- **THEN** two cards display side by side at the top of the page per the Details and Additional Details card rules above
- **AND** the CVE data displayed corresponds to the CVE ID from the route parameters

#### Scenario: Excluded components field with link when excluded present
- **WHEN** a user views the report page and the product has one or more entries in `product.data.excludedComponents`
- **THEN** the Details card displays "Excluded components" as a clickable link to `/reports/product/excluded-components/:productId/:cveId` with `<numExcluded>/<numSubmitted>` in the value

#### Scenario: Excluded components field as plain text when zero excluded
- **WHEN** a user views the report page and the product has zero excluded components (`excludedComponents` empty or undefined)
- **THEN** the Details card displays "Excluded components" with value `0/<numSubmitted>` (e.g. "0/10") as plain text, not a link

#### Scenario: Completed field when no date available
- **WHEN** a user views the report page and the report has no Date Completed
- **THEN** the Additional Details card displays the Completed field with value "-" or the `NotAvailable` component

#### Scenario: Metadata field with metadata present
- **WHEN** a user views the report page and the product has metadata in `product.data.metadata`
- **THEN** the Additional Details card displays a Metadata field below Completed with all key-value pairs as PatternFly Labels in "key:value" format

#### Scenario: Metadata field with no metadata
- **WHEN** a user views the report page and the product has no metadata in `product.data.metadata` (empty or undefined)
- **THEN** the Additional Details card displays the Metadata field with the `NotAvailable` component

### Requirement: CVE Status donut Chart
The report page SHALL display a donut chart summarizing CVE vulnerability statuses (vulnerable, not_vulnerable, uncertain) for the specific CVE ID from route parameters across all repository reports. The card title SHALL be "Findings". When data is present, the donut center SHALL show the total count with subtitle "Statuses". Slices SHALL map `product.summary.justificationStatusCounts` keys "TRUE", "FALSE", and "UNKNOWN" (case-insensitive) to vulnerable (red), not_vulnerable (green), and uncertain (orange) respectively. The chart SHALL include a legend with status labels and counts. All three statuses SHALL always be displayed, even when count is 0.

#### Scenario: CVE status donut chart displays
- **WHEN** a user views the report page with report data loaded and a specific CVE ID in the route
- **THEN** the "Findings" donut chart displays with slices, legend, and center total per the requirement above

#### Scenario: CVE status donut chart empty state
- **WHEN** no data is available for the specified CVE ID in the report
- **THEN** the donut chart displays an empty state message

#### Scenario: CVE status donut chart loading state
- **WHEN** report data is being fetched for the donut chart
- **THEN** the donut chart area displays a loading spinner

### Requirement: Component Scan States donut Chart
The report page SHALL display a donut chart summarizing component scan states from `sbomReport.statusCounts`, including components that have not been scanned. Each slice SHALL show the count for that state. The chart SHALL include a legend with state labels and counts. Component states SHALL appear in order: completed, expired, failed, queued, sent, pending (only states present in data), followed by any states not in that list (appended at the end with a default palette color). Predefined state colors SHALL be: completed (green), expired (orange), failed (red), queued (orange), sent (purple), pending (turquoise).

#### Scenario: Component states donut chart displays
- **WHEN** a user views the report page with report data loaded (including data with only predefined states, with unscanned components, or with states outside the predefined list)
- **THEN** the donut chart displays slices for each unique state from `sbomReport.statusCounts` in the required order and colors
- **AND** states not in the predefined list appear at the end using a default color from the color palette

#### Scenario: Component states donut chart empty state
- **WHEN** no component state data is available
- **THEN** the donut chart displays an empty state message

#### Scenario: Component states donut chart loading state
- **WHEN** report data is being fetched
- **THEN** the donut chart area displays a loading spinner

### Requirement: Repository Reports Table
The report page SHALL display an embedded repository reports table that conforms to the **repository-reports-table** specification, embedded under the donut charts in a separate `PageSection`. The table SHALL list repository reports filtered by both the report's SBOM report ID and the CVE ID from route parameters. The table SHALL automatically refresh using `usePaginatedApi` with live updates (`liveUpdatesRefresh`), using the same condition as the parent report page: refetch only when some analysis states in `sbomReport.statusCounts` are not "failed" or "completed". When all analysis states are either "failed" or "completed", live refetches SHALL stop. The repository reports table SHALL use the same `sbomReport.statusCounts` data from the parent report page to determine whether to continue (see `api-hooks` and `report-events-stream` specifications). Live refresh SHALL preserve current pagination, sorting, and filter settings and follow `shouldContinueLiveRefresh` from the parent product data (see `api-hooks`).

#### Scenario: Repository reports table displays on report page
- **WHEN** a user views the report page with a specific CVE ID in the route
- **THEN** a repository reports table displays per the repository-reports-table specification, filtered by SBOM report ID and CVE ID, embedded under the donut charts

#### Scenario: Repository reports table live refresh on report page
- **WHEN** a user views the report page with a repository reports table and some analysis states in `sbomReport.statusCounts` are not "failed" or "completed"
- **THEN** the table refreshes on SSE live-update events via `usePaginatedApi` (see `api-hooks` and `report-events-stream` specifications)
- **AND** when all analysis states are either "failed" or "completed", live refresh stops

#### Scenario: Repository reports table error state on report page
- **WHEN** reports data fetch fails for the repository reports table on the report page
- **THEN** the table displays an error message

#### Scenario: Repository reports table empty state on report page
- **WHEN** no repository reports are found for the SBOM report and CVE combination
- **THEN** the table displays an empty state message

### Requirement: Report Page Layout
The report page SHALL use PatternFly layout components and follow the standard page structure with `PageSection` components. Breadcrumb navigation at the top SHALL have: (1) "Reports" as a clickable link to `/reports`; (2) `<SBOM name>/<CVE ID>` as non-clickable text using `sbomReport.sbomName` and the CVE ID from route parameters. Below the breadcrumb, the page title SHALL be "Report: <SBOM name>/<CVE ID>" with "Report" in bold, SBOM name from `sbomReport.sbomName`, and CVE ID from route parameters. A status label SHALL appear next to the page title showing the SBOM report state (e.g. "Completed" with green label when `sbomReport.statusCounts["completed"]` exists). Report details SHALL appear in two side-by-side `Card` components in a `Grid` layout; donut charts SHALL appear side by side in a `Grid` layout; the repository reports table SHALL appear in a separate `PageSection` below the donut charts.

#### Scenario: Report page layout
- **WHEN** a user views the report page
- **THEN** the page displays breadcrumb, title, status label, detail cards, donut charts, and embedded repository table per the layout rules above
- **AND** clicking the "Reports" breadcrumb item navigates to `/reports`

### Requirement: API Integration
The report page SHALL use API calls for data fetching via hooks defined in the `api-hooks` capability (see `api-hooks` for `useApi`, `usePaginatedApi`, and `useReport`). Report data SHALL be fetched from `/api/v1/reports/product/${productId}` via `useReport`; the page SHALL extract and display data for the CVE ID from route parameters. Repository reports data SHALL be fetched from `/api/v1/reports` with `productId` and `vulnId` query parameters via `usePaginatedApi`, including pagination (`page`, `pageSize`), sorting (`sortBy`), and optional filters (`status`, `exploitIqStatus`, `gitRepo`). Live refresh via `useReport` on SSE SHALL run only while some analysis states in `sbomReport.statusCounts` are not "failed" or "completed", stopping via `shouldRefresh` on `useApi` when all states are "failed" or "completed", without disrupting the current view (see `api-hooks` and `report-events-stream`).

#### Scenario: Report data fetched via API
- **WHEN** the report page loads with SBOM report ID and CVE ID in route parameters
- **THEN** report data is fetched from `/api/v1/reports/product/${productId}` via `useReport` and displayed for the route CVE ID

#### Scenario: Repository reports data fetched via API
- **WHEN** the repository reports table loads with SBOM report ID and CVE ID in route parameters
- **THEN** reports data is fetched from `/api/v1/reports` with `productId`, `vulnId`, pagination, sorting, and optional filter parameters via `usePaginatedApi`

#### Scenario: Report page live refresh
- **WHEN** a user views the report page and some analysis states in `sbomReport.statusCounts` are not "failed" or "completed"
- **THEN** product data refreshes on SSE via `useReport` until all states are "failed" or "completed"

### Requirement: Dependency triage unavailable warning on product report page
When the product payload indicates that automated dependency triage was skipped because Exhort was not healthy at the start of SPDX whole-product processing, the product summary page at `/reports/product/:productId/:cveId` SHALL display a PatternFly **warning** `Alert` visible alongside the normal report layout. The alert **`title`** SHALL be exactly: `Dependency triage unavailable`. The alert **body/content** SHALL be exactly: `The automated pre-check for vulnerable packages is offline. Full analysis is being performed on all components to ensure complete coverage.`

#### Scenario: Alert shown when triage unavailable
- **WHEN** a user views the report page at `/reports/product/:productId/:cveId` and product data from `/api/v1/reports/product/${productId}` includes `dependencyTriageUnavailable === true` (or equivalent typed field from the generated client)
- **THEN** the page renders a PatternFly `Alert` with `variant="warning"` and the exact title and content strings above

#### Scenario: No alert when triage was available or legacy product
- **WHEN** a user views the report page at `/reports/product/:productId/:cveId` and `dependencyTriageUnavailable` is false, undefined, or absent (legacy persisted documents)
- **THEN** the page SHALL NOT render the Dependency triage unavailable warning alert

### Requirement: Product report page triage warnings
The product SBOM report page embedded repository table SHALL show the dependency triage warning icon only when the **per-repository report** has **`componentDependencyTriageFailed` true**. The table SHALL **not** infer per-row warnings from the product-level **`dependencyTriageUnavailable`** flag alone.

#### Scenario: Product triage skipped but no per-component failure
- **WHEN** a user views the product report page, the product has **`dependencyTriageUnavailable` true**, and all repository reports have **`componentDependencyTriageFailed` false** or absent
- **THEN** the repository table SHALL NOT show the triage warning icon for any row

#### Scenario: Per-component triage failure
- **WHEN** a user views the product report page and at least one embedded repository report has **`componentDependencyTriageFailed` true**
- **THEN** the repository table SHALL show the triage warning icon for those rows only (with the standard tooltip text)
