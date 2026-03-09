package com.redhat.ecosystemappeng.morpheus.model;

import org.eclipse.microprofile.openapi.annotations.media.Schema;
import io.quarkus.runtime.annotations.RegisterForReflection;

@Schema(name = "ParsedSpdxUnsupportedComponent", description = "Component without OCI purl (not sent through pipeline)")
@RegisterForReflection
public record ParsedSpdxUnsupportedComponent(
    @Schema(description = "SPDX identifier of the component package")
    String spdxId,
    @Schema(description = "Component name")
    String name,
    @Schema(description = "Component version")
    String version,
    @Schema(description = "Package URL if present, or null")
    String purl
) {}
