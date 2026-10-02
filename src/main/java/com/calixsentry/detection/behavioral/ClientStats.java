package com.calixsentry.detection.behavioral;

/**
 * Aggregated statistics for one client over the current behavioral window.
 * Computed on demand by ClientActivityTracker - never stored, always derived
 * fresh from the window so it reflects the true current state.
 */
public record ClientStats(
        int totalRequests,
        int uniquePaths,
        int notFoundCount,
        int forbiddenCount,
        int serverErrorCount,
        int sensitivePathHits,
        double averageIntervalMillis,
        double requestsPerSecond,
        int distinctMethods,
        boolean scannerUserAgentSeen
) {
    public double notFoundRatio() {
        return totalRequests == 0 ? 0.0 : (double) notFoundCount / totalRequests;
    }
}
