package com.redhat.ecosystemappeng.morpheus.service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class ProductProcessingService {

  private static final Logger LOGGER = Logger.getLogger(ProductProcessingService.class);
  
  private final ExecutorService executorService = Executors.newCachedThreadPool();

  @Inject
  SpdxParsingService spdxParsingService;

  @Inject
  ComponentProcessingService componentProcessingService;

  public void processAsync(String productId, JsonNode spdxJson) {
    CompletableFuture.runAsync(() -> {
      try {
        LOGGER.infof("Starting async processing for product: %s", productId);
        
        SpdxParsingService.ParsedSpdx parsed = spdxParsingService.parse(spdxJson);
        
        LOGGER.infof("Processing %d components for product: %s", parsed.components().size(), productId);
        
        // Build metadata for reports
        Map<String, String> metadata = new HashMap<>();
        metadata.put("product_id", productId);
        metadata.put("product_name", parsed.productInfo().name());
        if (parsed.productInfo().version() != null && !parsed.productInfo().version().isEmpty()) {
          metadata.put("product_version", parsed.productInfo().version());
        }
        
        // Process all components through the pipeline:
        // 1. Execute syft to get CycloneDX SBOM
        // 2. (Future) Call clair API for vulnerability scanning
        // 3. Call component syncer API
        // 4. Create report and add to queue
        componentProcessingService.processComponents(
            parsed.components(), 
            productId, 
            metadata
        ).join(); // Block until all components are processed
        
        LOGGER.infof("Completed async processing for product: %s", productId);
      } catch (Exception e) {
        LOGGER.errorf(e, "Error during async processing for product: %s", productId);
      }
    }, executorService);
  }
}

