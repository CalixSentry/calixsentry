package com.calixsentry.scoring;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.DetectionCategory;
import com.calixsentry.detection.DetectionResult;
import com.calixsentry.detection.Finding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Combines the outputs of every {@link com.calixsentry.detection.Detector}
 * into a single, explainable, normalized threat score.
 *
 * Design notes:
 *  - The score is a SUM of configurable weights from every triggered
 *    finding, capped at 100. It is deliberately simple/transparent rather
 *    than a black-box model, because every score must be explainable to an
 *    administrator (spec section 5 / 13).
 *  - Severity bands are configurable (scoring.lowMax/mediumMax/highMax).
 *  - "dominantCategory" is the category with the single largest score
 *    contribution, used as the event's headline classification.
 */
@Component
public class ThreatScoringEngine {

    private final CalixSentryProperties properties;

    public ThreatScoringEngine(CalixSentryProperties properties) {
        this.properties = properties;
    }

    public ThreatAssessment assess(List<DetectionResult> results) {
        List<DetectionResult> triggered = results.stream().filter(DetectionResult::triggered).toList();

        if (triggered.isEmpty()) {
            return new ThreatAssessment(0, ThreatLevel.LOW, DetectionCategory.NONE, List.of(), List.of());
        }

        int rawScore = 0;
        List<String> reasons = new ArrayList<>();
        DetectionResult dominant = null;
        int dominantScore = -1;

        for (DetectionResult result : triggered) {
            int contribution = result.totalScoreContribution();
            rawScore += contribution;
            for (Finding f : result.findings()) {
                reasons.add(f.reasonText());
            }
            if (contribution > dominantScore) {
                dominantScore = contribution;
                dominant = result;
            }
        }

        int normalized = Math.min(100, Math.max(0, rawScore));
        ThreatLevel level = classify(normalized);

        DetectionCategory dominantCategory = dominant != null ? dominant.category() : DetectionCategory.NONE;

        return new ThreatAssessment(normalized, level, dominantCategory, reasons, triggered);
    }

    private ThreatLevel classify(int score) {
        var s = properties.getScoring();
        if (score <= s.getLowMax()) return ThreatLevel.LOW;
        if (score <= s.getMediumMax()) return ThreatLevel.MEDIUM;
        if (score <= s.getHighMax()) return ThreatLevel.HIGH;
        return ThreatLevel.CRITICAL;
    }
}
