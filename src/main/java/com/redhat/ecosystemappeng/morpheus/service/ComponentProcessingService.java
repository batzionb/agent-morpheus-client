package com.redhat.ecosystemappeng.morpheus.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.redhat.ecosystemappeng.morpheus.client.ComponentSyncerService;
import com.redhat.ecosystemappeng.morpheus.model.ReportData;
import com.redhat.ecosystemappeng.morpheus.model.ReportRequest;
import com.redhat.ecosystemappeng.morpheus.model.morpheus.SbomInfoType;
import com.redhat.ecosystemappeng.morpheus.service.SpdxParsingService.ComponentInfo;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class ComponentProcessingService {

    private static final Logger LOGGER = Logger.getLogger(ComponentProcessingService.class);
    private static final int EXIT_CODE_SUCCESS = 0;
    private static final String SYFT_CACHE_DIR_ENV = "SYFT_CACHE_DIR";

    @ConfigProperty(name = "morpheus.syft.cache.dir")
    String syftCacheDir;

    @Inject
    ObjectMapper objectMapper;

    @Inject
    ReportService reportService;

    @RestClient
    ComponentSyncerService componentSyncerService;

    // Simple thread pool for component processing
    private final ExecutorService executorService = Executors.newCachedThreadPool();

    /**
     * Process a single component through the pipeline:
     * 1. Execute syft to generate CycloneDX SBOM
     * 2. (Future) Call clair API for vulnerability scanning
     * 3. Call component syncer API
     * 4. Create report and add to queue
     * 
     * @param component The SPDX component to process
     * @param productId The product ID this component belongs to
     * @param metadata Additional metadata to include in the report
     * @return CompletableFuture that completes when processing is done (or fails)
     */
    public CompletableFuture<Void> processComponent(ComponentInfo component, String productId, Map<String, String> metadata) {
        return CompletableFuture
            .supplyAsync(() -> executeSyft(component), executorService)
            .thenCompose(cycloneDxSbom -> {
                // Future: Add clair API call here
                // return callClairAPI(cycloneDxSbom).thenCompose(vulnData -> ...);
                return callComponentSyncer(cycloneDxSbom, component, productId)
                    .thenRun(() -> createAndQueueReport(cycloneDxSbom, component, productId, metadata));
            })
            .exceptionally(e -> {
                LOGGER.errorf(e, "Failed to process component %s: %s", component.name(), e.getMessage());
                return null;
            });
    }

    /**
     * Execute syft command to generate CycloneDX SBOM for a component.
     * Note: This assumes the component can be referenced as an image/package.
     * You may need to adjust how the syft target is constructed based on your component structure.
     */
    private JsonNode executeSyft(ComponentInfo component) {
        try {
            String syftTarget = buildSyftTarget(component);
            LOGGER.infof("Executing syft for component: %s (target: %s)", component.name(), syftTarget);
            
            String[] command = new String[] {
                "syft",
                syftTarget,
                "-o",
                "cyclonedx-json",
            };
            
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.environment().put(SYFT_CACHE_DIR_ENV, syftCacheDir);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append(System.lineSeparator());
                }
            }

            StringBuilder errorOutput = new StringBuilder();
            try (BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String errorLine;
                while ((errorLine = errorReader.readLine()) != null) {
                    errorOutput.append(errorLine).append(System.lineSeparator());
                }
            }

            int exitCode = process.waitFor();
            if (exitCode != EXIT_CODE_SUCCESS) {
                String rawError = errorOutput.toString();
                String cleanError = rawError.replaceAll("\u001B\\[[;\\d]*m", "");
                throw new IOException("Syft execution failed: " + cleanError.trim());
            }

            LOGGER.infof("Successfully generated CycloneDX SBOM for component: %s", component.name());
            return objectMapper.readTree(output.toString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("Failed to execute syft for component: " + component.name(), e);
        }
    }

    /**
     * Build the target string for syft command from component info.
     * This is a placeholder - adjust based on your component structure.
     * Options:
     * - Use purl if it's a container image reference
     * - Construct image name from component name:version
     * - Use a different approach based on your needs
     */
    private String buildSyftTarget(ComponentInfo component) {
        // Option 1: Use purl if it contains image reference
        if (component.purl() != null && component.purl().startsWith("pkg:oci/")) {
            // Extract image reference from OCI purl
            return component.purl().replace("pkg:oci/", "").split("\\?")[0];
        }
        
        // Option 2: Construct from name:version (adjust format as needed)
        if (component.version() != null && !component.version().isEmpty()) {
            return component.name() + ":" + component.version();
        }
        
        // Option 3: Just use name
        return component.name();
    }

    /**
     * Call component syncer API with the CycloneDX SBOM.
     * This creates a CloudEvent payload and sends it to the component syncer.
     */
    private CompletableFuture<Response> callComponentSyncer(JsonNode cycloneDxSbom, ComponentInfo component, String productId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Create CloudEvent payload for component syncer
                ObjectNode cloudEvent = objectMapper.createObjectNode();
                cloudEvent.put("specversion", "1.0");
                cloudEvent.put("type", "com.redhat.ecosystemappeng.morpheus.component.sbom");
                cloudEvent.put("source", "agent-morpheus-client");
                cloudEvent.put("id", UUID.randomUUID().toString());
                
                ObjectNode data = objectMapper.createObjectNode();
                data.put("product_id", productId);
                data.put("component_spdx_id", component.spdxId());
                data.put("component_name", component.name());
                data.put("component_version", component.version() != null ? component.version() : "");
                data.put("component_purl", component.purl() != null ? component.purl() : "");
                data.set("sbom", cycloneDxSbom);
                
                cloudEvent.set("data", data);
                
                LOGGER.infof("Calling component syncer API for component: %s", component.name());
                Response response = componentSyncerService.submit(cloudEvent);
                
                int status = response.getStatus();
                if (status >= Response.Status.OK.getStatusCode() && 
                    status < Response.Status.MULTIPLE_CHOICES.getStatusCode()) {
                    LOGGER.infof("Successfully called component syncer for component: %s", component.name());
                } else {
                    String errorBody = response.readEntity(String.class);
                    LOGGER.warnf("Component syncer returned status %d for component %s: %s", 
                        status, component.name(), errorBody);
                }
                
                return response;
            } catch (Exception e) {
                throw new RuntimeException("Failed to call component syncer API for component: " + component.name(), e);
            }
        }, executorService);
    }

    /**
     * Create a report from the CycloneDX SBOM and queue it for processing.
     */
    private void createAndQueueReport(JsonNode cycloneDxSbom, ComponentInfo component, 
                                      String productId, Map<String, String> metadata) {
        try {
            // Build metadata
            Map<String, String> reportMetadata = new HashMap<>();
            if (metadata != null) {
                reportMetadata.putAll(metadata);
            }
            reportMetadata.put("product_id", productId);
            reportMetadata.put("component_spdx_id", component.spdxId());
            reportMetadata.put("component_name", component.name());
            if (component.version() != null) {
                reportMetadata.put("component_version", component.version());
            }
            if (component.purl() != null) {
                reportMetadata.put("component_purl", component.purl());
            }

            // Create ReportRequest
            ReportRequest reportRequest = new ReportRequest(
                UUID.randomUUID().toString(), // id
                "image", // analysisType
                List.of(), // vulnerabilities - empty for now, can be populated from clair later
                null, // image
                cycloneDxSbom, // sbom
                SbomInfoType.CYCLONEDX_JSON, // sbomInfoType
                reportMetadata, // metadata
                null, // sourceRepo
                null, // commitId
                null, // ecosystem
                null // manifestPath
            );

            // Process and queue the report
            ReportData reportData = reportService.process(reportRequest);
            reportService.submit(reportData.reportRequestId().id(), reportData.report());
            
            LOGGER.infof("Created and queued report for component: %s (report ID: %s)", 
                component.name(), reportData.reportRequestId().id());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create and queue report for component: " + component.name(), e);
        }
    }

    /**
     * Process multiple components in parallel.
     * Concurrency is controlled by the thread pool size.
     * 
     * @param components List of components to process
     * @param productId The product ID
     * @param metadata Additional metadata
     * @return CompletableFuture that completes when all components are processed
     */
    public CompletableFuture<Void> processComponents(List<ComponentInfo> components, String productId, 
                                                    Map<String, String> metadata) {
        if (components.isEmpty()) {
            return CompletableFuture.completedFuture(null);
        }

        LOGGER.infof("Processing %d components", components.size());
        
        List<CompletableFuture<Void>> futures = components.stream()
            .map(component -> {
                return CompletableFuture.runAsync(() -> {
                    try {
                        processComponent(component, productId, metadata).join();
                    } catch (Exception e) {
                        LOGGER.errorf(e, "Error processing component %s", component.name());
                        throw e;
                    }
                }, executorService);
            })
            .toList();

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    }
}
