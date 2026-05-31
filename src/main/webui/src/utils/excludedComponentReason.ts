// SPDX-FileCopyrightText: Copyright (c) 2026, Red Hat Inc. & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/** User-visible Reason text for an ExcludedComponent row (see excluded-components-page spec). */
export function excludedComponentReasonText(
  exclusionType: string,
  error?: string
): string {
  if (exclusionType === "dependency_not_present") {
    return "Vulnerable package not in dependencies";
  }
  return error ?? "";  
}
