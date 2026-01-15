# reports-table Specification

## Purpose
The reports table displays vulnerability analysis reports in a tabular format, allowing users to view product-level analysis results. The table provides aggregate ExploitIQ status indicators that summarize the overall vulnerability posture of each product/SBOM.
## Requirements
### Requirement: Reports Table Display
The application SHALL display a table of vulnerability analysis reports with columns for SBOM name, CVE ID, Repositories Analyzed, ExploitIQ status, completion date, analysis state, and actions. The completion date column SHALL display dates in the format "DD Month YYYY, HH:MM:SS AM/PM TZ" (e.g., "07 July 2025, 10:14:02 PM EST"), including the day, full month name, year, time with seconds, AM/PM indicator, and timezone abbreviation. The reports table SHALL use the `/api/v1/reports/grouped` API endpoint to fetch data, which provides server-side grouping and aggregation for improved performance.

#### Scenario: Reports table displays product and CVE information
- **WHEN** a user views the reports page
- **THEN** the table displays one row per CVE per product with SBOM name, CVE ID, and other metadata
- **AND** the data is fetched from `/api/v1/reports/grouped` API endpoint

#### Scenario: Repositories Analyzed column displays
- **WHEN** a user views the reports table
- **THEN** the table displays a "Repositories Analyzed" column
- **AND** the column shows the format "analyzedCount / totalCount analyzed" where the values come from the `repositoriesAnalyzed` field in the `GroupedReportRow` response
- **AND** for reports with product_id, the value is aggregated server-side and provided in the API response
- **AND** for reports without product_id, the column may display "N/A" or be empty

#### Scenario: ExploitIQ status column shows all status counts per CVE
- **WHEN** a user views the reports table AND the analysis state is "completed"
- **THEN** the ExploitIQ status column displays all three status types with their counts: "X vulnerable" in a red label, "Y not vulnerable" in a green label, and "Z uncertain" in an orange label
- **AND** any status with a count of 0 is hidden (not displayed)
- **AND** the status counts are calculated from the grouped report data

#### Scenario: ExploitIQ status column shows blank during analysis
- **WHEN** a user views the reports table AND the analysis state is "analysing" (i.e., analysis has not yet finished)
- **THEN** the ExploitIQ status column displays nothing (blank/empty) to indicate the analysis is in progress

#### Scenario: View Report button is always enabled
- **WHEN** a user views the reports table
- **THEN** the "View Report" button is enabled and can be clicked to view the report, regardless of analysis state

#### Scenario: View Report button navigation
- **WHEN** a user clicks the "View Report" button in the actions column
- **THEN** the application navigates to `/Reports/:productId/:cveId` where `:productId` is the product ID and `:cveId` is the CVE ID from the row data
- **AND** if the row has no product_id, the navigation uses the image name or appropriate identifier

#### Scenario: Completion date column name and display
- **WHEN** a user views the reports table
- **THEN** the completion date column is labeled "Completion Date"
- **AND** when a report has a completion date, showing the date in the format "DD Month YYYY, HH:MM:SS AM/PM TZ" (e.g., "07 July 2025, 10:14:02 PM EST") when available, or " " when no completion date is available

#### Scenario: Default sorting by submittedAt
- **WHEN** a user first views the reports table
- **THEN** the table is sorted by submittedAt in descending order (newest reports first, oldest reports last) using server-side sorting
- **AND** the sorting is performed by the `/api/v1/reports/grouped` API endpoint
- **AND** the submittedAt column remains sortable by the user (ascending/descending)

#### Scenario: Server-side filtering and pagination
- **WHEN** a user applies filters or changes pagination on the reports table
- **THEN** the filters and pagination parameters are sent to the `/api/v1/reports/grouped` API endpoint
- **AND** the server performs filtering and pagination, returning only the requested page of filtered results
- **AND** the table displays the paginated results with correct total count from API response headers

