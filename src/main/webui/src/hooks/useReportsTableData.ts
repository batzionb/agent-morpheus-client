import { useMemo } from "react";
import { usePaginatedApi } from "./usePaginatedApi";
import { GroupedReportRow } from "../generated-client";
import { ReportsToolbarFilters } from "../components/ReportsToolbar";

export type ProductStatus = {
  vulnerableCount: number;
  notVulnerableCount: number;
  uncertainCount: number;
};

export interface ReportRow {
  reportId: string;
  sbomName: string;
  cveId: string;
  repositoriesAnalyzed: string;
  exploitIqStatus: string;
  exploitIqLabel: string;
  completedAt: string;
  analysisState: string;
  productStatus: ProductStatus;
}

export type SortDirection = "asc" | "desc";
export type SortColumn = "reportId" | "sbomName" | "completedAt" | "submittedAt";

export interface UseReportsTableOptions {
  searchValue: string;
  cveSearchValue: string;
  filters: ReportsToolbarFilters;
  sortColumn: SortColumn;
  sortDirection: SortDirection;
  page: number;
  perPage: number;
}

export interface UseReportsTableResult {
  rows: ReportRow[];
  loading: boolean;
  error: Error | null;
  pagination: {
    totalElements: number;
    totalPages: number;
  } | null;
}

// Note: calculateCveStatus removed - status counts not available in GroupedReportRow
// TODO: Enhance GroupedReportRow API to include status counts if needed

/**
 * Pure function to check if analysis is completed
 */
export function isAnalysisCompleted(analysisState: string): boolean {
  return analysisState === "completed";
}

/**
 * Status item with count and color
 */
export type StatusItem = {
  count: number;
  label: string;
  color: "red" | "green" | "orange";
};

/**
 * Pure function to get status items with their colors
 * Returns an array of status items, each with its own color
 * Always shows all three statuses (vulnerable, not vulnerable, uncertain) if their count > 0
 */
export function getStatusItems(productStatus: ProductStatus): StatusItem[] {
  const items: StatusItem[] = [];

  if (productStatus.vulnerableCount > 0) {
    items.push({
      count: productStatus.vulnerableCount,
      label: "Vulnerable",
      color: "red",
    });
  }

  if (productStatus.notVulnerableCount > 0) {
    items.push({
      count: productStatus.notVulnerableCount,
      label: "Not Vulnerable",
      color: "green",
    });
  }

  if (productStatus.uncertainCount > 0) {
    items.push({
      count: productStatus.uncertainCount,
      label: "Uncertain",
      color: "orange",
    });
  }

  return items;
}


/**
 * Pure function to transform grouped report rows into report rows
 * Converts GroupedReportRow (from API) to ReportRow (for table display)
 */
export function transformGroupedRowsToReportRows(
  groupedRows: GroupedReportRow[]
): ReportRow[] {
  return groupedRows.map((groupedRow) => {
    // Use productId as reportId/sbomName when available, otherwise use name
    const reportId = groupedRow.productId || groupedRow.name || "-";
    const sbomName = groupedRow.productId || groupedRow.name || "-";
    
    // Use repositoriesAnalyzed from API if available, otherwise empty
    const repositoriesAnalyzed = groupedRow.repositoriesAnalyzed || "-";
    
    // For reports without product_id, use state from API
    // For reports with product_id, we don't have state in GroupedReportRow
    // We'll need to determine this from other data or set a default
    const analysisState = groupedRow.state || "unknown";
    
    // Default productStatus (status counts not available in GroupedReportRow)
    // TODO: Enhance API to include status counts in GroupedReportRow
    const productStatus: ProductStatus = {
      vulnerableCount: 0,
      notVulnerableCount: 0,
      uncertainCount: 0,
    };

    return {
      reportId,
      sbomName,
      cveId: groupedRow.cveId || "-",
      repositoriesAnalyzed,
      exploitIqStatus: "unknown", // Not available in GroupedReportRow
      exploitIqLabel: "uncertain", // Not available in GroupedReportRow
      completedAt: "", // Not available in GroupedReportRow
      analysisState,
      productStatus,
    };
  });
}

/**
 * Pure function to compare two strings with natural sorting
 */
export function compareStrings(
  a: string,
  b: string,
  sortDirection: SortDirection
): number {
  const strA = (a || "").toLowerCase();
  const strB = (b || "").toLowerCase();
  const comparison = strA.localeCompare(strB, undefined, {
    numeric: true,
    sensitivity: "base",
  });
  return sortDirection === "asc" ? comparison : -comparison;
}

/**
 * Pure function to build sortBy parameter for API
 * Converts SortColumn and SortDirection to API format
 */
export function buildSortByParam(
  sortColumn: SortColumn,
  sortDirection: SortDirection
): string[] {
  // Map frontend sort columns to API sort fields
  const sortFieldMap: Record<SortColumn, string> = {
    reportId: "productId",
    sbomName: "productId",
    completedAt: "submittedAt",
    submittedAt: "submittedAt",
  };

  const apiField = sortFieldMap[sortColumn] || "submittedAt";
  const direction = sortDirection === "asc" ? "ASC" : "DESC";
  return [`${apiField}:${direction}`];
}

/**
 * Pure function to build filter parameters for API
 */
export function buildFilterParams(
  searchValue: string,
  cveSearchValue: string,
  filters: ReportsToolbarFilters
): Record<string, string | undefined> {
  const params: Record<string, string | undefined> = {};

  // Map search values to API filters
  // Note: The API doesn't support OR logic, so we'll search by productId first
  // If no results, user can try imageName search separately
  // For now, we'll use productId for grouped reports (most common case)
  if (searchValue.trim()) {
    params.productId = searchValue.trim();
  }

  if (cveSearchValue.trim()) {
    params.vulnId = cveSearchValue.trim();
  }

  // Map status filter
  if (filters.analysisState.length > 0) {
    params.status = filters.analysisState.join(",");
  }

  // ExploitIQ status filter
  if (filters.exploitIqStatus.length > 0) {
    // Map frontend labels to API values
    const statusMap: Record<string, string> = {
      "Vulnerable": "TRUE",
      "Not Vulnerable": "FALSE",
      "Uncertain": "UNKNOWN",
    };
    const apiStatuses = filters.exploitIqStatus
      .map((label) => statusMap[label])
      .filter(Boolean);
    if (apiStatuses.length > 0) {
      params.exploitIqStatus = apiStatuses.join(",");
    }
  }

  return params;
}

/**
 * Hook to fetch reports and process them for the reports table
 * Follows Rule VI: Complex data processing logic is encapsulated in a custom hook
 * with separate pure functions for data transformation
 * Uses the grouped API endpoint for server-side grouping and aggregation
 */
export function useReportsTableData(
  options: UseReportsTableOptions
): UseReportsTableResult {
  const {
    searchValue,
    cveSearchValue,
    filters,
    sortColumn,
    sortDirection,
    page,
    perPage,
  } = options;

  // Build API parameters
  const sortBy = useMemo(
    () => buildSortByParam(sortColumn, sortDirection),
    [sortColumn, sortDirection]
  );

  const filterParams = useMemo(
    () => buildFilterParams(searchValue, cveSearchValue, filters),
    [searchValue, cveSearchValue, filters]
  );

  // Fetch grouped reports using usePaginatedApi to get pagination headers
  const {
    data: groupedRows,
    loading,
    error,
    pagination,
  } = usePaginatedApi<Array<GroupedReportRow>>(
    () => ({
      method: "GET",
      url: "/api/v1/reports/grouped",
      query: {
        page: page - 1, // API uses 0-based, frontend uses 1-based
        pageSize: perPage,
        sortBy,
        ...filterParams,
      },
    }),
    {
      deps: [page, perPage, sortBy, filterParams],
    }
  );

  // Transform grouped rows to report rows
  const rows = useMemo(() => {
    if (!groupedRows) {
      return [];
    }
    return transformGroupedRowsToReportRows(groupedRows);
  }, [groupedRows]);

  return {
    rows,
    loading,
    error,
    pagination,
  };
}
