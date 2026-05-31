/*
 * SPDX-FileCopyrightText: Copyright (c) 2026, Red Hat Inc. & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.redhat.ecosystemappeng.morpheus.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Optional debug aid: when {@code morpheus.debug.exhort-syft-json-dump-directory} is non-empty,
 * writes pretty-printed Syft CycloneDX and Exhort HTTP payloads under
 * {@code <dir>/<productId>/<componentName>/}.
 */
@ApplicationScoped
public class ExhortSyftDebugDumpService {

  private static final Logger LOGGER = Logger.getLogger(ExhortSyftDebugDumpService.class);

  private static final int MAX_SEGMENT_LENGTH = 180;

  @Inject
  ObjectMapper objectMapper;

  @ConfigProperty(name = "morpheus.debug.exhort-syft-json-dump-directory", defaultValue = "")
  String dumpDirectory;

  public boolean isEnabled() {
    return dumpDirectory != null && !dumpDirectory.isBlank();
  }

  /**
   * Writes {@code <prefix>_cyclonedx.json} for Syft output.
   */
  public void dumpCycloneDx(String productId, String componentName, JsonNode sbomJson) {
    if (!isEnabled() || sbomJson == null) {
      return;
    }
    String prefix = safeFilePrefix(componentName);
    Path dir = resolveComponentDir(productId, componentName);
    if (dir == null) {
      return;
    }
    writePrettyJson(dir.resolve(prefix + "_cyclonedx.json"), sbomJson);
  }

  /**
   * Writes {@code <prefix>_exhort.json} from Exhort HTTP response (any status).
   */
  public void dumpExhortResponse(String productId, String componentName, int httpStatus, String body) {
    if (!isEnabled()) {
      return;
    }
    String prefix = safeFilePrefix(componentName);
    Path dir = resolveComponentDir(productId, componentName);
    if (dir == null) {
      return;
    }
    ObjectNode wrapper = objectMapper.createObjectNode();
    wrapper.put("httpStatus", httpStatus);
    if (body == null || body.isBlank()) {
      wrapper.putNull("body");
    } else {
      try {
        JsonNode parsed = objectMapper.readTree(body);
        wrapper.set("body", parsed);
      } catch (Exception e) {
        wrapper.put("bodyRaw", body);
        wrapper.put("bodyParseNote", "Response was not valid JSON; stored as bodyRaw.");
      }
    }
    writePrettyJson(dir.resolve(prefix + "_exhort.json"), wrapper);
  }

  /**
   * Writes {@code <prefix>_exhort.json} when the Exhort client call fails before a normal response.
   */
  public void dumpExhortCallFailure(String productId, String componentName, Throwable error) {
    if (!isEnabled()) {
      return;
    }
    String prefix = safeFilePrefix(componentName);
    Path dir = resolveComponentDir(productId, componentName);
    if (dir == null) {
      return;
    }
    ObjectNode node = objectMapper.createObjectNode();
    node.put("exhortCallFailed", true);
    node.put("message", error != null ? Objects.toString(error.getMessage(), "") : "");
    if (error != null) {
      node.put("exceptionClass", error.getClass().getName());
    }
    writePrettyJson(dir.resolve(prefix + "_exhort.json"), node);
  }

  private Path resolveComponentDir(String productId, String componentName) {
    Path base = Path.of(dumpDirectory.trim()).toAbsolutePath().normalize();
    Path dir = base.resolve(safePathSegment(productId)).resolve(safePathSegment(componentName));
    try {
      Files.createDirectories(dir);
    } catch (IOException e) {
      LOGGER.warnf(e, "Could not create debug dump directory %s", dir);
      return null;
    }
    return dir;
  }

  private void writePrettyJson(Path file, JsonNode node) {
    if (file == null) {
      return;
    }
    try {
      String pretty = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(node);
      Files.writeString(file, pretty, StandardCharsets.UTF_8);
      LOGGER.debugf("Wrote debug JSON: %s", file);
    } catch (IOException e) {
      LOGGER.warnf(e, "Could not write debug dump file %s", file);
    }
  }

  static String safePathSegment(String s) {
    if (s == null || s.isBlank()) {
      return "unknown";
    }
    String t = s.replaceAll("[^a-zA-Z0-9._-]+", "_").replaceAll("_{2,}", "_");
    t = t.replaceAll("^[_\\.]+|[_\\.]+$", "");
    if (t.isBlank()) {
      return "unknown";
    }
    if (t.length() > MAX_SEGMENT_LENGTH) {
      t = t.substring(0, MAX_SEGMENT_LENGTH);
    }
    return t;
  }

  /** File name prefix (same rules as path segment). */
  static String safeFilePrefix(String componentName) {
    return safePathSegment(componentName);
  }
}
