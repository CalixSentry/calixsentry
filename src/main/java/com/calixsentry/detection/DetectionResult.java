package com.calixsentry.detection;

import java.util.List;

/**
 * The outcome of a single detector run against one request (+ its client's
 * recent history, for behavioral detectors). A detector NEVER decides an
 * action - it only reports what it saw and why. The PolicyEngine decides
 * what happens next.
 */
public record DetectionResult(
        String ruleId,
        DetectionCategory category,
        boolean triggered,
        List<Finding> findings
) {
    public static DetectionResult none() {
        return new DetectionResult("NONE", DetectionCategory.NONE, false, List.of());
    }

    public int totalScoreContribution() {
        return findings.stream().mapToInt(Finding::scoreContribution).sum();
    }
}
