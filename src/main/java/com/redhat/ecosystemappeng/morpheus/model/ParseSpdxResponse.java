package com.redhat.ecosystemappeng.morpheus.model;

import java.util.List;

import org.eclipse.microprofile.openapi.annotations.media.Schema;
import io.quarkus.runtime.annotations.RegisterForReflection;

@Schema(name = "ParseSpdxResponse", description = "Result of parsing an SPDX document")
@RegisterForReflection
public record ParseSpdxResponse(
    @Schema(required = true, description = "Product information from the DESCRIBES package")
    ParsedSpdxProductInfo productInfo,
    @Schema(required = true, description = "Supported components (OCI image purl)")
    List<ParsedSpdxComponent> components,
    @Schema(required = true, description = "Unsupported components (no purl or non-OCI purl)")
    List<ParsedSpdxUnsupportedComponent> unsupportedComponents
) {}
