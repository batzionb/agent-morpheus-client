/*
 * SPDX-FileCopyrightText: Copyright (c) 2026, Red Hat Inc. & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.redhat.ecosystemappeng.morpheus.service;

import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import com.redhat.ecosystemappeng.morpheus.client.ExhortAnalysisClient;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

/**
 * Uses {@code POST /api/v5/analysis} with a minimal CycloneDX body (per upload-spdx / exhort-integration specs),
 * not HTTP GET health routes that hosted Exhort may not expose.
 */
@ApplicationScoped
public class ExhortHealthProbe {

  private static final Logger LOGGER = Logger.getLogger(ExhortHealthProbe.class);

  /** Matches WireMock {@code exhort-analysis-health-probe.json} for tests. */
  static final String HEALTH_PROBE_CYCLONE_DX =
      """
      {"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","bom-ref":"probe","name":"health-probe","version":"0"}}}
      """;

  @Inject
  @RestClient
  ExhortAnalysisClient exhortClient;

  public boolean probe() {
    try (Response response = exhortClient.analyze(null, HEALTH_PROBE_CYCLONE_DX)) {
      int status = response.getStatus();
      if (status >= 200 && status < 300) {
        return true;
      }
      LOGGER.infof("Exhort health probe returned HTTP %s", status);
      return false;
    } catch (Exception e) {
      LOGGER.infof("Exhort health probe failed: %s", e.getMessage());
      return false;
    }
  }
}
