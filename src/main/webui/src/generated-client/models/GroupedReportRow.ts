/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Grouped report row with product_id grouping or individual report without product_id
 */
export type GroupedReportRow = {
    /**
     * Product ID if report has product_id, null otherwise
     */
    productId?: string;
    /**
     * CVE ID
     */
    cveId: string;
    /**
     * Repositories analyzed (completed/total) - only for reports with product_id
     */
    repositoriesAnalyzed?: string;
    /**
     * Image name (only for reports without product_id)
     */
    name?: string;
    /**
     * Report state (only for reports without product_id)
     */
    state?: string;
};

