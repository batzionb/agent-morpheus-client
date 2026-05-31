/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Component excluded from scanning for a product
 */
export type ExcludedComponent = {
    /**
     * Component name
     */
    name: string;
    /**
     * Component version
     */
    version: string;
    /**
     * Component image or purl reference
     */
    image: string;
    /**
     * Reason category (e.g. error, dependency_not_present)
     */
    exclusionType: string;
    /**
     * Optional error detail when exclusionType is error
     */
    error?: string;
};

