package com.redhat.ecosystemappeng.morpheus.service;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.redhat.ecosystemappeng.morpheus.client.ComponentSyncerService;
import com.redhat.ecosystemappeng.morpheus.exception.ComponentSyncerSubmitException;
import com.redhat.ecosystemappeng.morpheus.exception.SbomValidationException;
import com.redhat.ecosystemappeng.morpheus.exception.SyftExecutionException;
import com.redhat.ecosystemappeng.morpheus.model.FailedComponent;
import com.redhat.ecosystemappeng.morpheus.model.ParsedCycloneDx;
import com.redhat.ecosystemappeng.morpheus.model.ReportData;
import com.redhat.ecosystemappeng.morpheus.repository.ProductRepositoryService;
import com.redhat.ecosystemappeng.morpheus.repository.ReportRepositoryService;
import com.redhat.ecosystemappeng.morpheus.service.SpdxParsingService.ComponentInfo;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

@ApplicationScoped
public class ComponentProcessingService {

    private static final Logger LOGGER = Logger.getLogger(ComponentProcessingService.class);

    private ObjectMapper objectMapper;
    private ReportService reportService;
    private GenerateSbomService generateSbomService;
    private ProductRepositoryService productRepositoryService;
    private ReportRepositoryService reportRepositoryService;
    private CredentialProcessingService credentialProcessingService;

    @Inject
    @RestClient
    private ComponentSyncerService componentSyncerService;

    // Fixed thread pool for component processing (max 10 concurrent)
    private final ExecutorService executorService = Executors.newFixedThreadPool(20);

    @Inject
    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Inject
    public void setReportService(ReportService reportService) {
        this.reportService = reportService;
    }

    @Inject
    public void setGenerateSbomService(GenerateSbomService generateSbomService) {
        this.generateSbomService = generateSbomService;
    }

    @Inject
    public void setProductRepositoryService(ProductRepositoryService productRepositoryService) {
        this.productRepositoryService = productRepositoryService;
    }

    @Inject
    public void setReportRepositoryService(ReportRepositoryService reportRepositoryService) {
        this.reportRepositoryService = reportRepositoryService;
    }

    @Inject
    public void setCredentialProcessingService(CredentialProcessingService credentialProcessingService) {
        this.credentialProcessingService = credentialProcessingService;
    }

    /**
     * Process a single component through the pipeline:
     * 1. Generate report (SBOM generation and report creation)
     * 2. Save report (submit to component syncer)
     * 
     * Failures before report creation are saved to product.submissionFailures.
     * Failures after report creation (component syncer submission) are saved to the report via updateWithError.
     * 
     * @param component The SPDX component to process
     * @param productId The product ID this component belongs to
     * @param metadata Additional metadata to include in the report
     * @param vulnerabilityId Optional vulnerability ID to include in the report
     * @param credentialId Optional credential ID to inject into the report
     */
    private void processComponent(ComponentInfo component, String productId, Map<String, String> metadata, String vulnerabilityId, String credentialId) {
        ReportData reportData = null;
        
        // Try to generate report - all failures here go to submissionFailures
        try {
            reportData = generateReport(component, productId, vulnerabilityId);
            String reportId = reportData.reportRequestId().reportId();
            LOGGER.infof("Created report %s for component: %s", reportId, component.name());
        } catch (SyftExecutionException e) {
            // Pre-save failure: Syft-specific error - save to submissionFailures
            // Expected exception - message is ready to use
            String image = e.getImage();
            LOGGER.errorf("Syft failed for component %s (image: %s): %s", component.name(), image, e.getMessage());
            productRepositoryService.addSubmissionFailure(productId, new FailedComponent(component.name(), component.version(), component.image(), e.getMessage()));
            return; // Exit early - no report to save
        } catch (SbomValidationException e) {
            // Pre-save failure: Validation error - save to submissionFailures
            // Expected exception - message is ready to use
            LOGGER.errorf("Sbom validation error for component %s: %s", component.name(), e.getMessage());
            productRepositoryService.addSubmissionFailure(productId, new FailedComponent(component.name(), component.version(), component.image(), e.getMessage()));
            return; // Exit early - no report to save
        } catch (Exception e) {
            // Pre-save failure: Any other error during report generation - save to submissionFailures
            // Unexpected exception - extract message
            String errorMessage = getErrorMessage(e);
            LOGGER.errorf("Failed to generate report for component %s: %s", component.name(), errorMessage);
            productRepositoryService.addSubmissionFailure(productId, new FailedComponent(component.name(), component.version(), component.image(), "Unexpected error during report generation"));
            return; // Exit early - no report to save
        }        
        // Inject credentialId into report if provided
        if (Objects.nonNull(credentialId) && Objects.nonNull(reportData.report())) {
            credentialProcessingService.injectCredentialId(reportData.report(), credentialId);
        }

        // Try to save report and submit to component syncer
        ReportData savedReportData = null;
        try {
            // First, save the report to the repository
            savedReportData = reportService.saveReport(reportData);
            String reportId = savedReportData.reportRequestId().reportId();
            LOGGER.infof("Saved report %s to repository for component: %s", reportId, component.name());
            
            // Then, submit cloud event to component syncer
            submitComponentAnalysisEvent(savedReportData);
            LOGGER.infof("Submitted component analysis event for report %s (component: %s)", reportId, component.name());
        } catch (ComponentSyncerSubmitException e) {
            // Post-save failure: Component syncer submission error - update report with error
            // Expected exception - message is ready to use
            String reportId = e.getReportId();
            LOGGER.errorf("Component syncer submission failed for component %s (report: %s): %s", component.name(), reportId, e.getMessage());
            reportRepositoryService.updateWithError(reportId, "component-syncer-submission-error", e.getMessage());
        } catch (Exception e) {
            // Post-save failure: Unexpected error during save or submission
            // If saveReport succeeded, we can update the report with error
            if (savedReportData != null) {
                String reportId = savedReportData.reportRequestId().id(); // Use id() for MongoDB ObjectId
                String errorMessage = getErrorMessage(e);
                LOGGER.errorf("Failed to submit report %s for component %s: %s", reportId, component.name(), errorMessage);
                reportRepositoryService.updateWithError(reportId, "unexpected-error", "Unexpected error during report generation");
            } else {
                // If saveReport failed, we don't have a saved report ID, so we can't update it
                // This is a database save failure - add to submissionFailures
                LOGGER.errorf("Failed to save report for component %s: %s", component.name(), getErrorMessage(e));
                productRepositoryService.addSubmissionFailure(productId, new FailedComponent(component.name(), component.version(), component.image(), "Unexpected error while saving report"));
            }
        }
    }

    /**
     * Generate a report for a component by generating the SBOM and creating report data.
     * This handles the pre-save phase of component processing.
     * 
     * @param component The component to generate a report for
     * @param productId The product ID this component belongs to
     * @param vulnerabilityId Optional vulnerability ID to include in the report
     * @return ReportData containing the created report
     * @throws SyftExecutionException if SBOM generation fails
     * @throws SbomValidationException if SBOM validation fails
     * @throws Exception for other pre-save failures
     */
    private ReportData generateReport(ComponentInfo component, String productId, String vulnerabilityId) 
            throws SyftExecutionException, SbomValidationException, Exception {
        String image = component.image();
        
        // Generate CycloneDX SBOM using GenerateSbomService
        ParsedCycloneDx cycloneDxSbom = generateSbomService.generate(image);
        LOGGER.infof("Generated CycloneDX SBOM for component: %s", component.name());

        // Create report data
        ReportData reportData = reportService.createCycloneDxReportData(cycloneDxSbom, productId, vulnerabilityId);
        LOGGER.infof("Created report data for component: %s", component.name());
        
        return reportData;
    }


    /**
     * Get error message from an exception.
     * For expected exceptions (SyftExecutionException, SbomValidationException, ComponentSyncerSubmitException),
     * the message is already available via getMessage() and doesn't need processing.
     * For unexpected exceptions, this method extracts a meaningful message.
     * 
     * @param e The exception to extract message from
     * @return A meaningful error message, never null
     */
    private String getErrorMessage(Exception e) {
        if (e.getMessage() != null && !e.getMessage().trim().isEmpty()) {
            return e.getMessage();
        }
        // If no message, use the exception class name
        return e.getClass().getSimpleName() + " occurred";
    }

    /**
     * Submit a component analysis cloud event to the component syncer.
     * Creates a CloudEvent with report_id and source_info extracted from the report.
     * 
     * @param reportData The report data containing the report ID and source information
     * @throws ComponentSyncerSubmitException if the report is missing required fields or if submission fails
     */
    private void submitComponentAnalysisEvent(ReportData reportData) {
        JsonNode report = reportData.report();
        String reportId = reportData.reportRequestId().id();
        
        // Extract source_info from report.input.image.source_info
        JsonNode input = report.get("input");
        if (input == null) {
            throw new ComponentSyncerSubmitException(reportId, "Report does not have input field");
        }
        
        JsonNode image = input.get("image");
        if (image == null) {
            throw new ComponentSyncerSubmitException(reportId, "Report does not have input.image field");
        }
        
        JsonNode sourceInfo = image.get("source_info");
        if (sourceInfo == null || !sourceInfo.isArray() || sourceInfo.size() == 0) {
            throw new ComponentSyncerSubmitException(reportId, "Report does not have source_info");
        }
        
        // Create cloud event structure
        ObjectNode cloudEvent = objectMapper.createObjectNode();
        cloudEvent.put("specversion", "1.0");
        cloudEvent.put("id", UUID.randomUUID().toString());
        cloudEvent.put("source", "agent.morpheus.client");
        cloudEvent.put("type", "component.analysis");
        cloudEvent.put("datacontenttype", "application/json");
        
        // Create data array with report entry
        ArrayNode dataArray = objectMapper.createArrayNode();
        ObjectNode reportEntry = objectMapper.createObjectNode();
        reportEntry.put("report_id", reportId);
        
        // Transform source_info to the required format
        // The source_info from the report already has the correct structure (git_repo, ref, type, include, exclude)
        reportEntry.set("source_info", sourceInfo);
        
        dataArray.add(reportEntry);
        cloudEvent.set("data", dataArray);
        
        LOGGER.infof("Submitting component analysis event for report %s", reportId);
        try {
            Response response = componentSyncerService.submit(cloudEvent);
            
            int status = response.getStatus();
            if (status >= Response.Status.OK.getStatusCode() && 
                status < Response.Status.MULTIPLE_CHOICES.getStatusCode()) {
                LOGGER.infof("Successfully submitted component analysis event for report %s", reportId);
            } else {
                String errorBody = response.readEntity(String.class);
                LOGGER.errorf("Component syncer returned status %d for report %s: %s", status, reportId, errorBody);
                throw new ComponentSyncerSubmitException(reportId, "Component syncer returned status " + status + ": " + errorBody);
            }
        } catch (ComponentSyncerSubmitException e) {
            throw e; // Re-throw our custom exception
        } catch (Exception e) {
            throw new ComponentSyncerSubmitException(reportId, "Failed to submit to component syncer", e);
        }
    }

    /**
     * Process multiple components in parallel (fire-and-forget).
     * Concurrency is controlled by the fixed thread pool size (max 10 concurrent).
     * 
     * @param components List of components to process
     * @param productId The product ID
     * @param metadata Additional metadata
     * @param vulnerabilityId Optional vulnerability ID to include in all component reports
     * @param credentialId Optional credential ID to inject into all component reports
     */
    public void processComponents(List<ComponentInfo> components, String productId, 
                                 Map<String, String> metadata, String vulnerabilityId, String credentialId) {
        if (components.isEmpty()) {
            throw new IllegalArgumentException("No components to process");
        }

        LOGGER.infof("Processing %d components (fire-and-forget)", components.size());
        
        // Fire off each component processing without waiting
        components.forEach(component -> {
            executorService.submit(() -> {
                try {
                    this.processComponent(component, productId, metadata, vulnerabilityId, credentialId);
                } catch (Exception e) {
                    String errorMessage = getErrorMessage(e);
                    LOGGER.errorf("Unexpected error processing component %s: %s", component.name(), errorMessage);
                }
            });
        });
    }
}
