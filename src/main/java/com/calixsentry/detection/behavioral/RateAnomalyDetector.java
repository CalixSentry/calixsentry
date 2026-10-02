package com.calixsentry.detection.behavioral;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.*;
import com.calixsentry.pipeline.RequestContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * CS-RATE-001 - Abnormal Request Rate Detection.
 *
 * Separate from {@link com.calixsentry.ratelimit.RateLimiter}: the rate
 * limiter is a hard, administrator-configured mechanical control (X req/s ->
 * 429). This detector is a SOFT behavioral signal that feeds the threat
 * score, using a higher bar than the rate limiter so it specifically flags
 * "very high" rates indicative of automated abuse rather than normal bursts.
 */
@Component
public class RateAnomalyDetector implements Detector {

    private final CalixSentryProperties properties;
    private final ClientActivityTracker tracker;

    public RateAnomalyDetector(CalixSentryProperties properties, ClientActivityTracker tracker) {
        this.properties = properties;
        this.tracker = tracker;
    }

    @Override public String ruleId() { return "CS-RATE-001"; }
    @Override public String name() { return "Abnormal Request Rate Detection"; }
    @Override public DetectionCategory category() { return DetectionCategory.RATE_ANOMALY; }
    @Override public Severity severity() { return Severity.MEDIUM; }
    @Override public String description() {
        return "Flags a client sustaining a very high request rate over the behavioral window - "
                + "a soft signal distinct from the hard, mechanical RateLimiter.";
    }
    @Override public boolean isEnabled() { return properties.getDetection().isBotScanning(); }

    @Override
    public DetectionResult evaluate(RequestContext context) {
        if (!isEnabled()) return DetectionResult.none();

        ClientStats stats = tracker.getStats(context.getClientIp());
        if (stats.totalRequests() < properties.getDetection().getEnumerationMinRequests()) {
            return DetectionResult.none();
        }
        if (stats.requestsPerSecond() < properties.getDetection().getVeryHighRequestsPerSecondThreshold()) {
            return DetectionResult.none();
        }

        List<Finding> findings = new ArrayList<>();
        findings.add(new Finding(
                String.format("Sustained request rate of %.1f req/s", stats.requestsPerSecond()),
                properties.getScoring().getWeightHighRequestRate()));
        return new DetectionResult(ruleId(), category(), true, findings);
    }
}
