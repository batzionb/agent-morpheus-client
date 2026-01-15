import { useState, useEffect } from "react";
import { Link } from "react-router";
import {
  Label,
  Flex,
  FlexItem,
  Alert,
  AlertVariant,
  Card,
  CardBody,
  Popover,
  Icon,
} from "@patternfly/react-core";
import { OutlinedQuestionCircleIcon } from "@patternfly/react-icons";
import { Table, Thead, Tr, Th, Tbody, Td } from "@patternfly/react-table";
import SkeletonTable from "@patternfly/react-component-groups/dist/dynamic/SkeletonTable";
import {
  useReportsTableData,
  SortDirection,
  SortColumn,
  getStatusItems,
  isAnalysisCompleted,
} from "../hooks/useReportsTableData";
import { ReportsToolbarFilters } from "./ReportsToolbar";
import ReportsToolbar from "./ReportsToolbar";
import { getErrorMessage } from "../utils/errorHandling";
import FormattedTimestamp from "./FormattedTimestamp";
import TableEmptyState from "./TableEmptyState";

interface ReportsTableProps {
  searchValue: string;
  onSearchChange: (value: string) => void;
  cveSearchValue: string;
  onCveSearchChange: (value: string) => void;
  filters: ReportsToolbarFilters;
  onFiltersChange: (filters: ReportsToolbarFilters) => void;
  analysisStateOptions: string[];
}

const ReportsTable: React.FC<ReportsTableProps> = ({
  searchValue,
  onSearchChange,
  cveSearchValue,
  onCveSearchChange,
  filters,
  onFiltersChange,
  analysisStateOptions,
}) => {
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(20);
  const [sortColumn, setSortColumn] = useState<SortColumn>("completedAt");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");

  // Use the custom hook for data fetching and processing (Rule VI)
  // Server-side pagination is handled by the API
  const {
    rows,
    loading,
    error,
    pagination,
  } = useReportsTableData({
    searchValue,
    cveSearchValue,
    filters,
    sortColumn,
    sortDirection,
    page,
    perPage,
  });

  const onPerPageSelect = (
    _event: React.MouseEvent | React.KeyboardEvent | MouseEvent,
    newPerPage: number,
    newPage: number
  ) => {
    setPerPage(newPerPage);
    setPage(newPage);
  };

  const columnNames = {
    reportId: "Report ID",
    cveId: "CVE ID",
    repositoriesAnalyzed: "Repositories Analyzed",
    exploitIqStatus: "ExploitIQ Status",
    completedAt: "Completion Date",
  };

  const handleSortToggle = (column: SortColumn) => {
    if (sortColumn === column) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortColumn(column);
      setSortDirection("asc");
    }
    setPage(1);
  };

  // Map sort columns to their column indices
  const getColumnIndex = (column: SortColumn): number => {
    switch (column) {
      case "reportId":
        return 0;
      case "completedAt":
        return 4;
      default:
        return 0;
    }
  };

  // Get the current sort index and direction for PatternFly
  const activeSortIndex = getColumnIndex(sortColumn);
  const activeSortDirection = sortDirection;

  useEffect(() => {
    setPage(1);
  }, [
    searchValue,
    cveSearchValue,
    filters.exploitIqStatus,
    filters.analysisState,
  ]);

  if (loading) {
    return (
      <SkeletonTable
        rowsCount={10}
        columns={[
          "Report ID",
          "CVE ID",
          "Repositories Analyzed",
          "ExploitIQ Status",
          "Completion Date",
        ]}
      />
    );
  }

  if (error) {
    return (
      <Card>
        <CardBody>
          <Alert variant={AlertVariant.danger} title="Error loading reports">
            {getErrorMessage(error)}
          </Alert>
        </CardBody>
      </Card>
    );
  }

  if (rows.length === 0) {
    return (
      <>
        <ReportsToolbar
          searchValue={searchValue}
          onSearchChange={onSearchChange}
          cveSearchValue={cveSearchValue}
          onCveSearchChange={onCveSearchChange}
          filters={filters}
          onFiltersChange={onFiltersChange}
          analysisStateOptions={analysisStateOptions}
          pagination={{
            itemCount: pagination?.totalElements ?? 0,
            page,
            perPage,
            onSetPage: (_event: unknown, newPage: number) => setPage(newPage),
            onPerPageSelect,
            perPageOptions: [
              { title: "10", value: 10 },
              { title: "20", value: 20 },
              { title: "50", value: 50 },
              { title: "100", value: 100 },
            ],
          }}
        />
        <TableEmptyState columnCount={5} titleText="No reports found" />
      </>
    );
  }

  return (
    <>
      <ReportsToolbar
        searchValue={searchValue}
        onSearchChange={onSearchChange}
        cveSearchValue={cveSearchValue}
        onCveSearchChange={onCveSearchChange}
        filters={filters}
        onFiltersChange={onFiltersChange}
        analysisStateOptions={analysisStateOptions}
          pagination={{
            itemCount: pagination?.totalElements ?? 0,
            page,
            perPage,
            onSetPage: (_event: unknown, newPage: number) => setPage(newPage),
            onPerPageSelect,
            perPageOptions: [
              { title: "10", value: 10 },
              { title: "20", value: 20 },
              { title: "50", value: 50 },
              { title: "100", value: 100 },
            ],
          }}
      />
      <Table aria-label="Reports table">
          <Thead>
            <Tr>
              <Th
                sort={{
                  sortBy: {
                    index: activeSortIndex,
                    direction: activeSortDirection,
                  },
                  onSort: () => handleSortToggle("reportId"),
                  columnIndex: 0,
                }}
              >
                {columnNames.reportId}
              </Th>
              <Th>{columnNames.cveId}</Th>
              <Th>{columnNames.repositoriesAnalyzed}</Th>
              <Th style={{ width: "25%" }}>
                <Flex
                  gap={{ default: "gapSm" }}
                  alignItems={{ default: "alignItemsCenter" }}
                >
                  <FlexItem>{columnNames.exploitIqStatus}</FlexItem>
                  <FlexItem>
                    <Popover
                      triggerAction="hover"
                      aria-label="ExploitIQ Status information"
                      bodyContent={
                        <div>
                          The status shows repository-level counts for this CVE.
                          All status types are displayed with their counts:
                          Vulnerable (red), Not Vulnerable (green), and
                          Uncertain (orange). Any status with a count of 0 is
                          hidden. The status is blank during analysis.
                        </div>
                      }
                    >
                      <Icon
                        role="button"
                        tabIndex={0}
                        aria-label="ExploitIQ Status help"
                        style={{
                          cursor: "help",
                          color: "var(--pf-v6-global--Color--200)",
                        }}
                      >
                        <OutlinedQuestionCircleIcon />
                      </Icon>
                    </Popover>
                  </FlexItem>
                </Flex>
              </Th>
              <Th
                sort={{
                  sortBy: {
                    index: activeSortIndex,
                    direction: activeSortDirection,
                  },
                  onSort: () => handleSortToggle("completedAt"),
                  columnIndex: 4,
                }}
              >
                {columnNames.completedAt}
              </Th>
            </Tr>
          </Thead>
          <Tbody>
            {rows.length === 0 ? (
              <Tr>
                <Td colSpan={5}>No reports found</Td>
              </Tr>
            ) : (
              rows.map((row, index) => {
                const isCompleted = isAnalysisCompleted(row.completedAt);
                // Determine navigation path based on reportType
                const navigationPath = row.reportType === "product"
                  ? `/Reports/product/${row.cveId}/${row.reportId}`
                  : `/Reports/component/${row.cveId}/${row.mongoId || row.reportId}`;
                
                return (
                  <Tr key={`${row.reportId}-${row.cveId}-${index}`}>
                    <Td
                      dataLabel={columnNames.reportId}
                      style={{
                        maxWidth: "10rem",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      <Link
                        to={navigationPath}
                        style={{
                          display: "block",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {row.reportId}
                      </Link>
                    </Td>
                    <Td dataLabel={columnNames.cveId}>{row.cveId}</Td>
                    <Td dataLabel={columnNames.repositoriesAnalyzed}>
                      {row.repositoriesAnalyzed}
                    </Td>
                    <Td dataLabel={columnNames.exploitIqStatus}>
                      {isCompleted
                        ? (() => {
                            const statusItems = getStatusItems(row.cveStatusCounts);
                            return statusItems.length > 0 ? (
                              <Flex gap={{ default: "gapSm" }}>
                                {statusItems.map((item, index) => (
                                  <FlexItem key={index}>
                                    <Label color={item.color}>
                                      {item.count} {item.label}
                                    </Label>
                                  </FlexItem>
                                ))}
                              </Flex>
                            ) : (
                              ""
                            );
                          })()
                        : ""}
                    </Td>
                    <Td dataLabel={columnNames.completedAt}>
                      {isCompleted ? (
                        <FormattedTimestamp date={row.completedAt} />
                      ) : (
                        ""
                      )}
                    </Td>
                  </Tr>
                );
              })
            )}
          </Tbody>
        </Table>
    </>
  );
};

export default ReportsTable;
