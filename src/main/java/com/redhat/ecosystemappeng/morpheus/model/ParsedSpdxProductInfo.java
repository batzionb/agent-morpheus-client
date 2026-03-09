package com.redhat.ecosystemappeng.morpheus.model;

import org.eclipse.microprofile.openapi.annotations.media.Schema;
import io.quarkus.runtime.annotations.RegisterForReflection;

@Schema(name = "ParsedSpdxProductInfo", description = "Product information extracted from SPDX document")
@RegisterForReflection
public record ParsedSpdxProductInfo(
    @Schema(description = "SPDX identifier of the product package")
    String spdxId,
    @Schema(description = "Product name")
    String name,
    @Schema(description = "Product version")
    String version,
    @Schema(description = "CPE identifier if present in product package externalRefs")
    String cpe
) {}
