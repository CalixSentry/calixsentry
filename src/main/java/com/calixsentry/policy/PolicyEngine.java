package com.calixsentry.policy;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.DetectionCategory;
import com.calixsentry.scoring.ThreatAssessment;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Set;

/**
 * Decides what to DO about a request, given what was DETECTED.
 *
 * This class deliberately contains NO detection logic - it only reads the
 * ThreatAssessment produced upstream and the administrator's configured
 * ProtectionMode. That separation (spec section 2) is what lets CalixSentry
 * run in MONITOR mode and record everything it *would* have blocked, without
 * ever touching live traffic - the safest possible default.
 *
 * Explicit blocks (manual admin action, active BlockStore entries) and rate
 * limiting are handled earlier in the pipeline (WafGatewayFilter) and never
 * flow through this class - this class only governs the DETECTION-driven
 * response.
 */
@Component
public class PolicyEngine {

    private final CalixSentryProperties properties;

    /** Categories with hard, signature-level evidence eligible for automatic action. */
    private static final Set<DetectionCategory> HARD_EVIDENCE_CATEGORIES = Set.of(
            DetectionCategory.SQL_INJECTION,
            DetectionCategory.CROSS_SITE_SCRIPTING,
            DetectionCategory.PATH_TRAVERSAL,
            DetectionCategory.COMMAND_INJECTION,
            DetectionCategory.ENDPOINT_ENUMERATION
    );

    public PolicyEngine(CalixSentryProperties properties) {
        this.properties = properties;
    }

    public PolicyDecision decide(ThreatAssessment assessment) {
        if (assessment.isClean()) {
            return PolicyDecision.allow();
        }

        ProtectionMode mode = resolveMode();
        var protection = properties.getProtection();

        Action recommended = recommendAction(assessment);
        Duration recommendedDuration = recommended == Action.TEMPORARY_BLOCK
                ? protection.getAutomaticBlockDuration()
                : null;

        return switch (mode) {
            case MONITOR -> new PolicyDecision(
                    Action.LOG, recommended,
                    "MONITOR mode: activity recorded only, no action taken on traffic.",
                    recommendedDuration);

            case ALERT -> {
                Action action = assessment.score() >= protection.getAlertThreshold() ? Action.ALERT : Action.LOG;
                yield new PolicyDecision(action, recommended,
                        "ALERT mode: traffic is never blocked; alert raised when score >= "
                                + protection.getAlertThreshold() + ".",
                        recommendedDuration);
            }

            case MANUAL -> {
                Action action = assessment.score() >= protection.getAlertThreshold() ? Action.ALERT : Action.LOG;
                yield new PolicyDecision(action, recommended,
                        "MANUAL mode: recommended action surfaced for an administrator to apply; "
                                + "traffic is never blocked automatically in this mode.",
                        recommendedDuration);
            }

            case AUTOMATIC -> {
                if (!protection.isAutomaticBlocking()) {
                    // Mode says AUTOMATIC but the explicit master switch is off - never
                    // silently auto-block (spec section 3: "must NEVER be enabled silently").
                    Action action = assessment.score() >= protection.getAlertThreshold() ? Action.ALERT : Action.LOG;
                    yield new PolicyDecision(action, recommended,
                            "AUTOMATIC mode selected but protection.automaticBlocking is false - "
                                    + "no automatic blocking will occur until explicitly enabled.",
                            recommendedDuration);
                }
                boolean eligible = HARD_EVIDENCE_CATEGORIES.contains(assessment.dominantCategory())
                        && assessment.score() >= protection.getAutomaticBlockThreshold();
                if (eligible) {
                    yield new PolicyDecision(Action.TEMPORARY_BLOCK, Action.TEMPORARY_BLOCK,
                            "AUTOMATIC mode: score " + assessment.score() + " >= threshold "
                                    + protection.getAutomaticBlockThreshold() + " with hard evidence category "
                                    + assessment.dominantCategory() + ".",
                            protection.getAutomaticBlockDuration());
                }
                Action action = assessment.score() >= protection.getAlertThreshold() ? Action.ALERT : Action.LOG;
                yield new PolicyDecision(action, recommended,
                        "AUTOMATIC mode: score below automatic-block threshold ("
                                + protection.getAutomaticBlockThreshold() + ") or evidence not eligible for auto-block.",
                        recommendedDuration);
            }
        };
    }

    private Action recommendAction(ThreatAssessment assessment) {
        var s = properties.getScoring();
        var protection = properties.getProtection();
        if (assessment.score() >= protection.getAutomaticBlockThreshold()) {
            return Action.TEMPORARY_BLOCK;
        }
        if (assessment.score() > s.getMediumMax()) {
            return Action.RATE_LIMIT;
        }
        if (assessment.score() >= protection.getAlertThreshold()) {
            return Action.ALERT;
        }
        return Action.LOG;
    }

    private ProtectionMode resolveMode() {
        try {
            return ProtectionMode.valueOf(properties.getProtection().getMode().trim().toUpperCase());
        } catch (Exception e) {
            // Fail SAFE, never fail open into a blocking mode on a config typo.
            return ProtectionMode.MONITOR;
        }
    }
}
