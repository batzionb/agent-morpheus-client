/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ExcludedComponent } from './ExcludedComponent';
/**
 * Product metadata
 */
export type Product = {
    /**
     * Product ID
     */
    id: string;
    /**
     * Product name
     */
    name: string;
    /**
     * Product version
     */
    version: string;
    /**
     * Timestamp of product scan request submission
     */
    submittedAt: string;
    /**
     * Number of components submitted for scanning
     */
    submittedCount: number;
    /**
     * Product user provided metadata
     */
    metadata: Record<string, string>;
    /**
     * Timestamp of product scan request completion
     */
    completedAt?: string;
    /**
     * Components excluded from scanning (errors or dependency gate)
     */
    excludedComponents: Array<ExcludedComponent>;
    /**
     * When true, whole-product Exhort health probe failed and per-component dependency triage was skipped
     */
    dependencyTriageUnavailable?: boolean;
    /**
     * CVE ID associated with this product
     */
    cveId: string;
};

