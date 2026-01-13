package com.redhat.ecosystemappeng.morpheus.model;

import io.quarkus.runtime.annotations.RegisterForReflection;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(name = "ReportError", description = "Error information for a failed report")
@RegisterForReflection
public record ReportError(
    @Schema(required = true, description = "Error type")
    String type,
    @Schema(required = true, description = "Error message")
    String message) {
  
}

