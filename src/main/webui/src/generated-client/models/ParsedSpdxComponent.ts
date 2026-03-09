/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Supported component with OCI image purl
 */
export type ParsedSpdxComponent = {
    /**
     * SPDX identifier of the component package
     */
    spdxId?: string;
    /**
     * Component name
     */
    name?: string;
    /**
     * Component version
     */
    version?: string;
    /**
     * Package URL (purl), must start with pkg:oci/
     */
    purl?: string;
    /**
     * Resolved OCI image reference (repository_url@sha256:hash)
     */
    image?: string;
};

