package com.calixsentry.scoring;

import com.calixsentry.detection.DetectionCategory;
import com.calixsentry.detection.DetectionResult;

import java.util.List;

/**
 * The combined output of every detector run for a single request: a
 * normalized 0-100 score, its severity band, the dominant category (used for
 * the event's headline classification), and every contributing reason - this
 * is exactly what powers the dashboard's "Why was this detected?" view.
 *
 * The score is a DECISION SIGNAL for the policy engine, not an absolute
 * verdict - see spec section 5.
 */
public record ThreatAssessment(
        int score,
        ThreatLevel level,
        DetectionCategory dominantCategory,
        List<String> reasons,
        List<DetectionResult> triggeredDetections
) {
    public boolean isClean() {
        return triggeredDetections.isEmpty();
    }
}
