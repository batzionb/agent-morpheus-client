/*
 * SPDX-FileCopyrightText: Copyright (c) 2026, Red Hat Inc. & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.redhat.ecosystemappeng.morpheus.client;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@RegisterRestClient(configKey = "exhort")
@Path("/api/v5")
public interface ExhortAnalysisClient {

  @POST
  @Path("/analysis")
  @Consumes("application/vnd.cyclonedx+json")
  Response analyze(@QueryParam("cves") String cves, String body);
}
