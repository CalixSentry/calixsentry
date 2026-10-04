package com.calixsentry.detection.behavioral;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.*;
import com.calixsentry.pipeline.RequestContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * CS-BOT-001 - Automated Endpoint Enumeration Detection.
 *
 * This is the core behavioral detector described in the product spec: it
 * recognizes a client hitting many distinct, often-unrelated URLs in a short
 * window, with a high failure (404/403) ratio, and/or repeated hits against
 * known-sensitive paths - the signature of automated scanning tools like
 * dirbuster/gobuster/ffuf/nikto - even when each individual request is
 * unremarkable.
 *
 * Deliberately requires a MINIMUM sample size
 * (detection.enumerationMinRequests) before judging anything, so a handful
 * of genuine 404s from a real user never trigger this detector. See
 * spec section 25 "False Positive Protection".
 */
@Component
public class EndpointEnumerationDetector implements Detector {

    private final CalixSentryProperties properties;
    private final ClientActivityTracker tracker;

    public EndpointEnumerationDetector(CalixSentryProperties properties, ClientActivityTracker tracker) {
        this.properties = properties;
        this.tracker = tracker;
    }

    @Override public String ruleId() { return "CS-BOT-001"; }
    @Override public String name() { return "Automated Endpoint Enumeration Detection"; }
    @Override public DetectionCategory category() { return DetectionCategory.ENDPOINT_ENUMERATION; }
    @Override public Severity severity() { return Severity.HIGH; }
    @Override public String description() {
        return "Detects automated endpoint/directory scanning by combining unique-path count, "
                + "404 ratio, sensitive-path hit count, and request cadence over a rolling "
                + "window (default 5 minutes). Requires a minimum request sample before judging, "
                + "to avoid false positives on small numbers of genuine 404s.";
    }
    @Override public boolean isEnabled() { return properties.getDetection().isEndpointEnumeration(); }

    @Override
    public DetectionResult evaluate(RequestContext context) {
        if (!isEnabled()) return DetectionResult.none();

        ClientStats stats = tracker.getStats(context.getClientIp());
        var detCfg = properties.getDetection();
        var scoreCfg = properties.getScoring();

        if (stats.totalRequests() < detCfg.getEnumerationMinRequests()) {
            return DetectionResult.none(); // sample too small to judge - avoid false positives
        }

        List<Finding> findings = new ArrayList<>();

        boolean highUniquePaths = stats.uniquePaths() >= detCfg.getEnumerationUniquePathThreshold();
        if (highUniquePaths) {
            findings.add(new Finding(
                    stats.uniquePaths() + " unique URLs requested within "
                            + detCfg.getEnumerationWindowSeconds() + "s",
                    scoreCfg.getWeightEndpointEnumeration()));
        }

        boolean highNotFoundRatio = stats.notFoundRatio() >= detCfg.getEnumerationNotFoundRatioThreshold();
        if (highNotFoundRatio) {
            findings.add(new Finding(
                    String.format("%.0f%% of requests returned 404", stats.notFoundRatio() * 100),
                    scoreCfg.getWeightHighNotFoundRatio()));
        }

        if (stats.sensitivePathHits() >= detCfg.getSensitivePathHitsThreshold()) {
            findings.add(new Finding(
                    stats.sensitivePathHits() + " known-sensitive paths requested",
                    scoreCfg.getWeightSensitivePaths()));
        }

        boolean burstBehavior = stats.averageIntervalMillis() > 0
                && stats.averageIntervalMillis() < detCfg.getMinRequestIntervalMillisForBurst()
                && stats.totalRequests() >= detCfg.getEnumerationMinRequests();
        if (burstBehavior) {
            findings.add(new Finding(
                    String.format("Request interval averaged %.0fms (automated cadence)", stats.averageIntervalMillis()),
                    scoreCfg.getWeightBurstBehavior()));
        }

        if (stats.scannerUserAgentSeen()) {
            findings.add(new Finding("Suspicious/automated User-Agent seen in this client's recent activity",
                    scoreCfg.getWeightSuspiciousUserAgent()));
        }

        // Require at least TWO independent behavioral signals before calling this
        // "endpoint enumeration" - this is the false-positive guard from spec section 25:
        // never decide on one weak signal alone.
        boolean triggered = findings.size() >= 2 && (highUniquePaths || highNotFoundRatio);
        if (!triggered) {
            return DetectionResult.none();
        }

        return new DetectionResult(ruleId(), category(), true, findings);
    }
}
