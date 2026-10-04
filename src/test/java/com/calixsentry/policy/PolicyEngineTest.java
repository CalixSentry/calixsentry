package com.calixsentry.policy;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.DetectionCategory;
import com.calixsentry.detection.DetectionResult;
import com.calixsentry.detection.Finding;
import com.calixsentry.scoring.ThreatAssessment;
import com.calixsentry.scoring.ThreatLevel;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PolicyEngineTest {

    private ThreatAssessment highScoreEnumerationAssessment(int score) {
        DetectionResult r = new DetectionResult("CS-BOT-001", DetectionCategory.ENDPOINT_ENUMERATION, true,
                List.of(new Finding("many unique paths", score)));
        return new ThreatAssessment(score, ThreatLevel.CRITICAL, DetectionCategory.ENDPOINT_ENUMERATION,
                List.of("many unique paths"), List.of(r));
    }

    @Test
    void monitorModeNeverBlocksRegardlessOfScore() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getProtection().setMode("MONITOR");
        props.getProtection().setAutomaticBlocking(true); // even if someone flips this, MONITOR must not block
        PolicyEngine engine = new PolicyEngine(props);

        PolicyDecision decision = engine.decide(highScoreEnumerationAssessment(95));

        assertEquals(Action.LOG, decision.action());
        assertNotEquals(Action.BLOCK, decision.action());
        assertNotEquals(Action.TEMPORARY_BLOCK, decision.action());
    }

    @Test
    void alertModeNeverBlocksButRaisesAlertAboveThreshold() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getProtection().setMode("ALERT");
        props.getProtection().setAlertThreshold(30);
        PolicyEngine engine = new PolicyEngine(props);

        PolicyDecision decision = engine.decide(highScoreEnumerationAssessment(95));
        assertEquals(Action.ALERT, decision.action());

        PolicyDecision lowDecision = engine.decide(highScoreEnumerationAssessment(10));
        assertEquals(Action.LOG, lowDecision.action());
    }

    @Test
    void manualModeSurfacesRecommendationButNeverBlocks() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getProtection().setMode("MANUAL");
        PolicyEngine engine = new PolicyEngine(props);

        PolicyDecision decision = engine.decide(highScoreEnumerationAssessment(95));
        assertNotEquals(Action.BLOCK, decision.action());
        assertNotEquals(Action.TEMPORARY_BLOCK, decision.action());
        assertEquals(Action.TEMPORARY_BLOCK, decision.recommendedAction(), "MANUAL mode should still recommend a block for review");
    }

    @Test
    void automaticModeDoesNotBlockUnlessMasterSwitchExplicitlyEnabled() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getProtection().setMode("AUTOMATIC");
        props.getProtection().setAutomaticBlocking(false); // explicitly OFF, per safe-default requirement
        PolicyEngine engine = new PolicyEngine(props);

        PolicyDecision decision = engine.decide(highScoreEnumerationAssessment(95));
        assertNotEquals(Action.TEMPORARY_BLOCK, decision.action(),
                "AUTOMATIC mode must never block while automaticBlocking master switch is off");
    }

    @Test
    void automaticModeBlocksOnlyWhenEnabledAndThresholdMet() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getProtection().setMode("AUTOMATIC");
        props.getProtection().setAutomaticBlocking(true);
        props.getProtection().setAutomaticBlockThreshold(80);
        PolicyEngine engine = new PolicyEngine(props);

        PolicyDecision below = engine.decide(highScoreEnumerationAssessment(60));
        assertNotEquals(Action.TEMPORARY_BLOCK, below.action());

        PolicyDecision above = engine.decide(highScoreEnumerationAssessment(90));
        assertEquals(Action.TEMPORARY_BLOCK, above.action());
        assertNotNull(above.blockDuration());
    }

    @Test
    void cleanTrafficAlwaysAllowsRegardlessOfMode() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getProtection().setMode("AUTOMATIC");
        props.getProtection().setAutomaticBlocking(true);
        PolicyEngine engine = new PolicyEngine(props);

        ThreatAssessment clean = new ThreatAssessment(0, ThreatLevel.LOW, DetectionCategory.NONE, List.of(), List.of());
        assertEquals(Action.ALLOW, engine.decide(clean).action());
    }

    @Test
    void invalidModeConfigurationFailsSafeToMonitor() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getProtection().setMode("NOT_A_REAL_MODE");
        props.getProtection().setAutomaticBlocking(true);
        PolicyEngine engine = new PolicyEngine(props);

        PolicyDecision decision = engine.decide(highScoreEnumerationAssessment(99));
        assertNotEquals(Action.TEMPORARY_BLOCK, decision.action(), "A bad config value must never fail open into blocking");
    }
}
