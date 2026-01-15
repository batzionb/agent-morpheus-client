/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Grouped report row with product_id grouping or individual report without product_id
 */
export type GroupedReportRow = {
    /**
     * Report ID: product_id if product, actual report ID (input.scan.id) if component
     */
    reportId?: string;
    /**
     * Report type: 'product' or 'component'
     */
    reportType: string;
    /**
     * CVE ID
     */
    cveId: string;
    /**
     * Repositories analyzed: 'completed/total' for products, '1' for components
     */
    repositoriesAnalyzed?: string;
    /**
     * ExploitIQ status counts: Map<Status, Count> - aggregated for products, single report for components
     */
    cveStatusCounts?: Record<string, number>;
    /**
     * Completion timestamp
     */
    completedAt?: string;
    /**
     * MongoDB document ID (_id) - used for navigation links
     */
    mongoId?: string;
};

