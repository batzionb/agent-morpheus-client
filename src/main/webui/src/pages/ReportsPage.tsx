import { useState } from "react";
import { PageSection, Title } from "@patternfly/react-core";
import ReportsTable from "../components/ReportsTable";
import { ReportsToolbarFilters } from "../components/ReportsToolbar";

const ReportsPage: React.FC = () => {
  const [searchValue, setSearchValue] = useState("");
  const [cveSearchValue, setCveSearchValue] = useState("");
  const [filters, setFilters] = useState<ReportsToolbarFilters>({
    exploitIqStatus: [],
    analysisState: [],
  });

  // Static list of analysis state options
  // These match the status values supported by the API
  const analysisStateOptions = [
    "completed",
    "sent",
    "failed",
    "queued",
    "expired",
    "pending",
    "analysing",
  ];

  return (
    <>
      <PageSection>
        <Title headingLevel="h1" size="3xl">
          Reports
        </Title>
        <p>
          View comprehensive report for your product and their security
          analysis. Reports include CVE exploitability assessments, VEX status
          justifications, and detailed analysis summaries.
        </p>
      </PageSection>
      <PageSection>
        <ReportsTable
          searchValue={searchValue}
          onSearchChange={setSearchValue}
          cveSearchValue={cveSearchValue}
          onCveSearchChange={setCveSearchValue}
          filters={filters}
          onFiltersChange={setFilters}
          analysisStateOptions={analysisStateOptions}
        />
      </PageSection>
    </>
  );
};

export default ReportsPage;
