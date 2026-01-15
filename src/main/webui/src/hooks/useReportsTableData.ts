import { useMemo } from "react";
import { usePaginatedApi } from "./usePaginatedApi";
import { GroupedReportRow } from "../generated-client";
import { ReportsToolbarFilters } from "../components/ReportsToolbar";

// ProductStatus type removed - using cveStatusCounts directly from GroupedReportRow

export interface ReportRow {
  reportId: string;
  reportType: string;
  cveId: string;
  repositoriesAnalyzed: string;
  cveStatusCounts?: Record<string, number>;
  completedAt: string;
  mongoId?: string;
}

export type SortDirection = "asc" | "desc";
export type SortColumn = "reportId" | "completedAt" | "submittedAt";

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
 * Uses completedAt field from GroupedReportRow
 */
export function isAnalysisCompleted(completedAt: string): boolean {
  return completedAt !== null && completedAt !== undefined && completedAt !== "";
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
 * Pure function to get status items with their colors from cveStatusCounts
 * Returns an array of status items, each with its own color
 * cveStatusCounts is a direct map from status to count (since each row is for one CVE)
 */
export function getStatusItems(
  cveStatusCounts: Record<string, number> | undefined
): StatusItem[] {
  const items: StatusItem[] = [];

  if (!cveStatusCounts) {
    return items;
  }

  // Map API status values to display labels and colors
  const statusMap: Record<string, { label: string; color: "red" | "green" | "orange" }> = {
    TRUE: { label: "Vulnerable", color: "red" },
    FALSE: { label: "Not Vulnerable", color: "green" },
    UNKNOWN: { label: "Uncertain", color: "orange" },
  };

  Object.entries(cveStatusCounts).forEach(([status, count]) => {
    if (count > 0 && statusMap[status]) {
      items.push({
        count,
        label: statusMap[status].label,
        color: statusMap[status].color,
      });
    }
  });

  return items;
}


/**
 * Pure function to transform grouped report rows into report rows
 * Maps GroupedReportRow fields directly to ReportRow (columns map directly to API fields)
 */
export function transformGroupedRowsToReportRows(
  groupedRows: GroupedReportRow[]
): ReportRow[] {
  return groupedRows.map((groupedRow) => {
    return {
      reportId: groupedRow.reportId || "-",
      reportType: groupedRow.reportType || "component",
      cveId: groupedRow.cveId || "-",
      repositoriesAnalyzed: groupedRow.repositoriesAnalyzed || "-",
      cveStatusCounts: groupedRow.cveStatusCounts,
      completedAt: groupedRow.completedAt || "",
      mongoId: groupedRow.mongoId,
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
