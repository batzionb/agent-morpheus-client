package com.redhat.ecosystemappeng.morpheus.model;

import io.quarkus.runtime.annotations.RegisterForReflection;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(name = "GroupedReportRow", description = "Grouped report row with product_id grouping or individual report without product_id")
@RegisterForReflection
public record GroupedReportRow(
    @Schema(description = "Product ID if report has product_id, null otherwise")
    String productId,
    
    @Schema(required = true, description = "CVE ID")
    String cveId,
    
    @Schema(description = "Repositories analyzed (completed/total) - only for reports with product_id")
    String repositoriesAnalyzed,
    
    @Schema(description = "Image name (only for reports without product_id)")
    String name,
    
    @Schema(description = "Report state (only for reports without product_id)")
    String state
) {}

