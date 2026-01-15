package com.redhat.ecosystemappeng.morpheus.model;

import java.util.Map;
import io.quarkus.runtime.annotations.RegisterForReflection;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Schema(name = "GroupedReportRow", description = "Grouped report row with product_id grouping or individual report without product_id")
@RegisterForReflection
public record GroupedReportRow(
    @Schema(description = "Report ID: product_id if product, actual report ID (input.scan.id) if component")
    String reportId,
    
    @Schema(required = true, description = "Report type: 'product' or 'component'")
    String reportType,
    
    @Schema(required = true, description = "CVE ID")
    String cveId,
    
    @Schema(description = "Repositories analyzed: 'completed/total' for products, '1' for components")
    String repositoriesAnalyzed,
    
    @Schema(description = "ExploitIQ status counts: Map<Status, Count> - aggregated for products, single report for components")
    Map<String, Integer> cveStatusCounts,
    
    @Schema(description = "Completion timestamp")
    String completedAt,
    
    @Schema(description = "MongoDB document ID (_id) - used for navigation links")
    String mongoId
) {}

