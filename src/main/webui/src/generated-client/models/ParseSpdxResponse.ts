/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ParsedSpdxComponent } from './ParsedSpdxComponent';
import type { ParsedSpdxProductInfo } from './ParsedSpdxProductInfo';
import type { ParsedSpdxUnsupportedComponent } from './ParsedSpdxUnsupportedComponent';
/**
 * Result of parsing an SPDX document
 */
export type ParseSpdxResponse = {
    /**
     * Product information from the DESCRIBES package
     */
    productInfo: ParsedSpdxProductInfo;
    /**
     * Supported components (OCI image purl)
     */
    components: Array<ParsedSpdxComponent>;
    /**
     * Unsupported components (no purl or non-OCI purl)
     */
    unsupportedComponents: Array<ParsedSpdxUnsupportedComponent>;
};

