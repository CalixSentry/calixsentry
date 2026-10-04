package com.calixsentry.scoring;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.DetectionCategory;
import com.calixsentry.detection.DetectionResult;
import com.calixsentry.detection.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ThreatScoringEngineTest {

    private final CalixSentryProperties props = new CalixSentryProperties();
    private final ThreatScoringEngine engine = new ThreatScoringEngine(props);

    @Test
    void cleanTrafficScoresZeroAndIsLow() {
        ThreatAssessment assessment = engine.assess(List.of(DetectionResult.none()));
        assertEquals(0, assessment.score());
        assertEquals(ThreatLevel.LOW, assessment.level());
        assertTrue(assessment.isClean());
    }

    @Test
    void scoreIsSumOfFindingsCappedAt100() {
        DetectionResult r1 = new DetectionResult("CS-A", DetectionCategory.SQL_INJECTION, true,
                List.of(new Finding("sqli", 60)));
        DetectionResult r2 = new DetectionResult("CS-B", DetectionCategory.CROSS_SITE_SCRIPTING, true,
                List.of(new Finding("xss", 60)));
        ThreatAssessment assessment = engine.assess(List.of(r1, r2));
        assertEquals(100, assessment.score());
        assertEquals(ThreatLevel.CRITICAL, assessment.level());
    }

    @Test
    void classifiesBandsAccordingToConfiguredThresholds() {
        assertEquals(ThreatLevel.LOW, scoreOf(10));
        assertEquals(ThreatLevel.MEDIUM, scoreOf(45));
        assertEquals(ThreatLevel.HIGH, scoreOf(70));
        assertEquals(ThreatLevel.CRITICAL, scoreOf(95));
    }

    @Test
    void reasonsAreCollectedFromAllTriggeredDetectors() {
        DetectionResult r = new DetectionResult("CS-BOT-001", DetectionCategory.ENDPOINT_ENUMERATION, true,
                List.of(new Finding("312 unique URLs in 5 minutes", 30),
                        new Finding("94% of requests returned 404", 15)));
        ThreatAssessment assessment = engine.assess(List.of(r));
        assertEquals(2, assessment.reasons().size());
        assertEquals(DetectionCategory.ENDPOINT_ENUMERATION, assessment.dominantCategory());
    }

    private ThreatLevel scoreOf(int points) {
        DetectionResult r = new DetectionResult("CS-X", DetectionCategory.NONE, true, List.of(new Finding("x", points)));
        return engine.assess(List.of(r)).level();
    }
}
