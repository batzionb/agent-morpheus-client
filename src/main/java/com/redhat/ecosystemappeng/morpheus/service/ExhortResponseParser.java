/*
 * SPDX-FileCopyrightText: Copyright (c) 2026, Red Hat Inc. & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.redhat.ecosystemappeng.morpheus.service;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redhat.ecosystemappeng.morpheus.exception.ExhortCveGateException;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class ExhortResponseParser {

  private static final String EXHORT_FIELD_PROVIDERS = "providers";
  private static final String EXHORT_FIELD_STATUS = "status";
  private static final String EXHORT_FIELD_OK = "ok";
  private static final String EXHORT_FIELD_WARNINGS = "warnings";
  private static final String EXHORT_FIELD_SOURCES = "sources";
  private static final String EXHORT_FIELD_DEPENDENCIES = "dependencies";
  private static final String EXHORT_FIELD_ISSUES = "issues";
  private static final String EXHORT_FIELD_TRANSITIVE = "transitive";
  private static final String EXHORT_FIELD_ID = "id";
  private static final String EXHORT_FIELD_CVES = "cves";

  @Inject
  ObjectMapper objectMapper;

  @Inject
  CycloneDxParsingService cycloneDxParsingService;

  public boolean cveFoundInAnalysisResponse(String analysisJson, String vulnerabilityId, String cycloneDxJson) {
    requireNonBlankCve(vulnerabilityId);
    JsonNode cdxRoot = parseCdxRoot(cycloneDxJson);
    JsonNode root = parseAnalysisRoot(analysisJson);
    Set<String> mainBases = cycloneDxParsingService.collectSyftMainModuleBasePurls(cdxRoot);
    validateAggregateProviders(root, mainBases);
    String cve = vulnerabilityId.trim();
    JsonNode providers = root.get(EXHORT_FIELD_PROVIDERS);
    Iterator<String> pids = providers.fieldNames();
    while (pids.hasNext()) {
      if (walkProviderForCve(providers.get(pids.next()), cve)) {
        return true;
      }
    }
    return false;
  }

  public Set<String> collectCveIdsFromAnalysisResponse(String analysisJson, String cycloneDxJson) {
    JsonNode cdxRoot = parseCdxRoot(cycloneDxJson);
    JsonNode root = parseAnalysisRoot(analysisJson);
    Set<String> mainBases = cycloneDxParsingService.collectSyftMainModuleBasePurls(cdxRoot);
    validateAggregateProviders(root, mainBases);
    JsonNode providers = root.get(EXHORT_FIELD_PROVIDERS);
    Set<String> out = new HashSet<>();
    Iterator<String> pids = providers.fieldNames();
    while (pids.hasNext()) {
      collectFromProvider(providers.get(pids.next()), out);
    }
    return out;
  }

  private static void requireNonBlankCve(String vulnerabilityId) {
    if (vulnerabilityId == null || vulnerabilityId.isBlank()) {
      throw new ExhortCveGateException("CVE id is required for triage");
    }
  }

  private JsonNode parseCdxRoot(String cycloneDxJson) {
    if (cycloneDxJson == null || cycloneDxJson.isBlank()) {
      throw new ExhortCveGateException("CycloneDX JSON is required for triage interpretation");
    }
    try {
      JsonNode n = objectMapper.readTree(cycloneDxJson);
      if (!n.isObject()) {
        throw new ExhortCveGateException("CycloneDX root must be a JSON object");
      }
      return n;
    } catch (JsonProcessingException e) {
      throw new ExhortCveGateException("Invalid CycloneDX JSON: " + e.getMessage());
    }
  }

  private JsonNode parseAnalysisRoot(String analysisJson) {
    try {
      JsonNode n = objectMapper.readTree(analysisJson);
      if (!n.isObject()) {
        throw new ExhortCveGateException("Analysis root must be a JSON object");
      }
      return n;
    } catch (JsonProcessingException e) {
      throw new ExhortCveGateException("Invalid Exhort analysis JSON: " + e.getMessage());
    }
  }

  private void validateAggregateProviders(JsonNode root, Set<String> mainModuleBases) {
    JsonNode providers = root.get(EXHORT_FIELD_PROVIDERS);
    if (providers == null || providers.isNull() || !providers.isObject() || !providers.fieldNames().hasNext()) {
      throw new ExhortCveGateException("Exhort analysis providers missing, empty, or not an object");
    }
    Iterator<String> names = providers.fieldNames();
    while (names.hasNext()) {
      JsonNode report = providers.get(names.next());
      if (!report.isObject()) {
        throw new ExhortCveGateException("Provider report must be an object");
      }
      validateProviderStatus(report.get(EXHORT_FIELD_STATUS), mainModuleBases);
    }
  }

  private void validateProviderStatus(JsonNode status, Set<String> mainModuleBases) {
    if (status == null || status.isNull() || !status.isObject()) {
      throw new ExhortCveGateException("Provider status missing or not an object");
    }
    JsonNode okNode = status.get(EXHORT_FIELD_OK);
    if (okNode == null || okNode.isNull() || !okNode.isBoolean() || !okNode.booleanValue()) {
      throw new ExhortCveGateException("Provider status.ok must be true");
    }
    assertWarningsAcceptable(status.get(EXHORT_FIELD_WARNINGS), mainModuleBases);
  }

  private void assertWarningsAcceptable(JsonNode warnings, Set<String> mainModuleBases) {
    if (warnings == null || warnings.isNull()) {
      return;
    }
    if (warnings.isObject()) {
      if (!warnings.fieldNames().hasNext()) {
        return;
      }
      Iterator<String> keys = warnings.fieldNames();
      while (keys.hasNext()) {
        String key = keys.next();
        String base = CycloneDxParsingService.basePurlForExhortWarningMatch(key);
        if (!mainModuleBases.contains(base)) {
          throw new ExhortCveGateException("Provider status.warnings are not empty (non–main-module warnings present)");
        }
      }
      return;
    }
    if (warnings.isArray()) {
      if (warnings.isEmpty()) {
        return;
      }
      throw new ExhortCveGateException("Provider status.warnings must be empty for triage");
    }
    throw new ExhortCveGateException("Provider status.warnings must be an object, array, or empty");
  }

  private boolean walkProviderForCve(JsonNode providerReport, String cve) {
    JsonNode sources = providerReport.get(EXHORT_FIELD_SOURCES);
    if (sources == null || sources.isNull()) {
      return false;
    }
    if (!sources.isObject()) {
      throw new ExhortCveGateException("sources must be an object when present");
    }
    Iterator<String> skeys = sources.fieldNames();
    while (skeys.hasNext()) {
      if (walkSourceDependencies(sources.get(skeys.next()), cve)) {
        return true;
      }
    }
    return false;
  }

  private void collectFromProvider(JsonNode providerReport, Set<String> out) {
    JsonNode sources = providerReport.get(EXHORT_FIELD_SOURCES);
    if (sources == null || sources.isNull()) {
      return;
    }
    if (!sources.isObject()) {
      throw new ExhortCveGateException("sources must be an object when present");
    }
    Iterator<String> skeys = sources.fieldNames();
    while (skeys.hasNext()) {
      collectFromSource(sources.get(skeys.next()), out);
    }
  }

  private boolean walkSourceDependencies(JsonNode sourceNode, String cve) {
    JsonNode deps = sourceNode.get(EXHORT_FIELD_DEPENDENCIES);
    if (deps == null || deps.isNull()) {
      return false;
    }
    requireArray(deps, EXHORT_FIELD_DEPENDENCIES);
    for (JsonNode row : deps) {
      if (walkDependencyRow(row, cve)) {
        return true;
      }
    }
    return false;
  }

  private void collectFromSource(JsonNode sourceNode, Set<String> out) {
    JsonNode deps = sourceNode.get(EXHORT_FIELD_DEPENDENCIES);
    if (deps == null || deps.isNull()) {
      return;
    }
    requireArray(deps, EXHORT_FIELD_DEPENDENCIES);
    for (JsonNode row : deps) {
      collectFromDependencyRow(row, out);
    }
  }

  private boolean walkDependencyRow(JsonNode depRow, String cve) {
    if (!depRow.isObject()) {
      throw new ExhortCveGateException("dependency row must be an object");
    }
    if (issuesMatch(depRow.get(EXHORT_FIELD_ISSUES), cve)) {
      return true;
    }
    JsonNode trans = depRow.get(EXHORT_FIELD_TRANSITIVE);
    if (trans == null || trans.isNull() || (trans.isArray() && trans.isEmpty())) {
      return false;
    }
    requireArray(trans, EXHORT_FIELD_TRANSITIVE);
    for (JsonNode child : trans) {
      if (walkDependencyRow(child, cve)) {
        return true;
      }
    }
    return false;
  }

  private void collectFromDependencyRow(JsonNode depRow, Set<String> out) {
    if (!depRow.isObject()) {
      throw new ExhortCveGateException("dependency row must be an object");
    }
    collectFromIssues(depRow.get(EXHORT_FIELD_ISSUES), out);
    JsonNode trans = depRow.get(EXHORT_FIELD_TRANSITIVE);
    if (trans == null || trans.isNull() || (trans.isArray() && trans.isEmpty())) {
      return;
    }
    requireArray(trans, EXHORT_FIELD_TRANSITIVE);
    for (JsonNode child : trans) {
      collectFromDependencyRow(child, out);
    }
  }

  private boolean issuesMatch(JsonNode issues, String cve) {
    if (issues == null || issues.isNull() || (issues.isArray() && issues.isEmpty())) {
      return false;
    }
    requireArray(issues, EXHORT_FIELD_ISSUES);
    for (JsonNode issue : issues) {
      if (!issue.isObject()) {
        throw new ExhortCveGateException("issue entry must be an object");
      }
      JsonNode idNode = issue.get(EXHORT_FIELD_ID);
      if (idNode != null && !idNode.isNull() && idNode.isTextual()
          && cve.equals(idNode.asText().trim())) {
        return true;
      }
      JsonNode cves = issue.get(EXHORT_FIELD_CVES);
      if (cves != null && !cves.isNull()) {
        requireArray(cves, EXHORT_FIELD_CVES);
        for (JsonNode c : cves) {
          if (c.isTextual() && cve.equals(c.asText().trim())) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private void collectFromIssues(JsonNode issues, Set<String> out) {
    if (issues == null || issues.isNull() || (issues.isArray() && issues.isEmpty())) {
      return;
    }
    requireArray(issues, EXHORT_FIELD_ISSUES);
    for (JsonNode issue : issues) {
      if (!issue.isObject()) {
        throw new ExhortCveGateException("issue entry must be an object");
      }
      JsonNode idNode = issue.get(EXHORT_FIELD_ID);
      if (idNode != null && !idNode.isNull() && idNode.isTextual()) {
        String t = idNode.asText().trim();
        if (!t.isEmpty()) {
          out.add(t);
        }
      }
      JsonNode cves = issue.get(EXHORT_FIELD_CVES);
      if (cves == null || cves.isNull()) {
        continue;
      }
      requireArray(cves, EXHORT_FIELD_CVES);
      for (JsonNode c : cves) {
        if (c.isTextual()) {
          String t = c.asText().trim();
          if (!t.isEmpty()) {
            out.add(t);
          }
        }
      }
    }
  }

  private static void requireArray(JsonNode n, String fieldLabel) {
    if (!n.isArray()) {
      throw new ExhortCveGateException(fieldLabel + " must be an array when present for traversal");
    }
  }
}
