package com.redhat.ecosystemappeng.morpheus.model;

import org.eclipse.microprofile.openapi.annotations.media.Schema;
import io.quarkus.runtime.annotations.RegisterForReflection;

@Schema(name = "ParsedSpdxComponent", description = "Supported component with OCI image purl")
@RegisterForReflection
public record ParsedSpdxComponent(
    @Schema(description = "SPDX identifier of the component package")
    String spdxId,
    @Schema(description = "Component name")
    String name,
    @Schema(description = "Component version")
    String version,
    @Schema(description = "Package URL (purl), must start with pkg:oci/")
    String purl,
    @Schema(description = "Resolved OCI image reference (repository_url@sha256:hash)")
    String image
) {}
