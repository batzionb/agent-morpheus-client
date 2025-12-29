package com.redhat.ecosystemappeng.morpheus.service;

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

  public void processAsync(String productId, JsonNode spdxJson) {
    CompletableFuture.runAsync(() -> {
      try {
        LOGGER.infof("Starting async processing for product: %s", productId);
        
        SpdxParsingService.ParsedSpdx parsed = spdxParsingService.parse(spdxJson);
        
        LOGGER.infof("Processing %d components for product: %s", parsed.components().size(), productId);
        
        for (SpdxParsingService.ComponentInfo component : parsed.components()) {
          LOGGER.infof("Processing component for product %s: SPDXID=%s, name=%s, version=%s, purl=%s", 
              productId, 
              component.spdxId(), 
              component.name(), 
              component.version(),
              component.purl() != null ? component.purl() : "N/A");
        }
        
        LOGGER.infof("Completed async processing for product: %s", productId);
      } catch (Exception e) {
        LOGGER.errorf(e, "Error during async processing for product: %s", productId);
      }
    }, executorService);
  }
}

