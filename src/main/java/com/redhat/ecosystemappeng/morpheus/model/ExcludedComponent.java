/*
 * SPDX-FileCopyrightText: Copyright (c) 2026, Red Hat Inc. & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.redhat.ecosystemappeng.morpheus.model;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

import io.quarkus.runtime.annotations.RegisterForReflection;

@Schema(name = "ExcludedComponent", description = "Component excluded from scanning for a product")
@RegisterForReflection
public record ExcludedComponent(
    @Schema(required = true, description = "Component name")
    String name,
    @Schema(required = true, description = "Component version")
    String version,
    @Schema(required = true, description = "Component image or purl reference")
    String image,
    @Schema(required = true, description = "Reason category (e.g. error, dependency_not_present)")
    String exclusionType,
    @Schema(description = "Optional error detail when exclusionType is error")
    String error) {

  public ExcludedComponent(String name, String version, String image, String exclusionType) {
    this(name, version, image, exclusionType, null);
  }
}
