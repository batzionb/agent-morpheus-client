/*
 * SPDX-FileCopyrightText: Copyright (c) 2026, Red Hat Inc. & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.redhat.ecosystemappeng.morpheus.model;

import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

import io.quarkus.runtime.annotations.RegisterForReflection;

@Schema(name = "Product", description = "Product metadata")
@RegisterForReflection
public record Product(
    @Schema(required = true, description = "Product ID")
    String id,
    @Schema(required = true, description = "Product name")
    String name,
    @Schema(required = true, description = "Product version")
    String version,
    @Schema(required = true, description = "Timestamp of product scan request submission")
    String submittedAt,
    @Schema(required = true, description = "Number of components submitted for scanning")
    int submittedCount,
    @Schema(required = true, description = "Product user provided metadata")
    Map<String, String> metadata,
    @Schema(description = "Timestamp of product scan request completion")
    String completedAt,
    @Schema(type = SchemaType.ARRAY, implementation = ExcludedComponent.class, required = true, description = "Components excluded from scanning (errors or dependency gate)")
    List<ExcludedComponent> excludedComponents,
    @Schema(description = "When true, whole-product Exhort health probe failed and per-component dependency triage was skipped")
    boolean dependencyTriageUnavailable,
    @Schema(required = true, description = "CVE ID associated with this product")
    String cveId
) {}
