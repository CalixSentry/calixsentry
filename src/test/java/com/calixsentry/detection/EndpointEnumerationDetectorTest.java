package com.calixsentry.detection;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.behavioral.ClientActivityTracker;
import com.calixsentry.detection.behavioral.EndpointEnumerationDetector;
import com.calixsentry.detection.signature.ScannerUserAgentDetector;
import com.calixsentry.pipeline.RequestContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simulates the exact attacker pattern from the product spec:
 *   GET /, GET /admin, GET /.env, GET /.git/config, GET /wp-admin, GET /phpinfo.php,
 *   GET /config.php, GET /backup.zip, GET /server-status, GET /random-path-N...
 * and verifies CalixSentry recognizes it as endpoint enumeration even though each
 * individual request is an unremarkable 404/403 by itself - while normal browsing
 * with a handful of unique pages and one incidental 404 must NOT trigger.
 */
class EndpointEnumerationDetectorTest {

    private CalixSentryProperties lowThresholdProperties() {
        CalixSentryProperties props = new CalixSentryProperties();
        // Scaled-down thresholds so a fast unit test can exercise the same logic
        // production uses with higher, noise-tolerant thresholds. Unique-path and
        // not-found-ratio thresholds are kept clearly ABOVE what the "normal
        // browsing" test below produces, and clearly BELOW what the "scanning"
        // test produces, so the two cases stay well separated.
        props.getDetection().setEnumerationMinRequests(10);
        props.getDetection().setEnumerationUniquePathThreshold(20);
        props.getDetection().setEnumerationNotFoundRatioThreshold(0.7);
        props.getDetection().setSensitivePathHitsThreshold(3);
        return props;
    }

    private RequestContext requestFor(String path) {
        return new RequestContext("9.9.9.9", "GET", path, path, "", Map.of(), "python-requests/2.31", 0, null, Instant.now());
    }

    @Test
    void recognizesScanningPatternAcrossMostlyUniqueFailingRequests() {
        CalixSentryProperties props = lowThresholdProperties();
        ScannerUserAgentDetector uaDetector = new ScannerUserAgentDetector(props);
        ClientActivityTracker tracker = new ClientActivityTracker(props, uaDetector);
        EndpointEnumerationDetector detector = new EndpointEnumerationDetector(props, tracker);

        List<String> scanPaths = new ArrayList<>(List.of(
                "/", "/admin", "/.env", "/.git/config", "/wp-admin",
                "/phpinfo.php", "/config.php", "/backup.zip", "/server-status"
        ));
        for (int i = 1; i <= 16; i++) {
            scanPaths.add("/random-path-" + i);
        }

        DetectionResult last = DetectionResult.none();
        for (String path : scanPaths) {
            var record = tracker.recordRequest("9.9.9.9", path, "GET", "python-requests/2.31");
            record.setStatus(path.equals("/") ? 200 : 404); // everything except "/" is a miss
            last = detector.evaluate(requestFor(path));
        }

        assertTrue(last.triggered(), "Expected endpoint enumeration to be detected for a 25-path scanning sequence");
        assertTrue(last.totalScoreContribution() > 0);
        assertTrue(last.findings().size() >= 2, "Detection must combine multiple independent signals, not one alone");
    }

    @Test
    void doesNotTriggerOnASingle404() {
        CalixSentryProperties props = lowThresholdProperties();
        ScannerUserAgentDetector uaDetector = new ScannerUserAgentDetector(props);
        ClientActivityTracker tracker = new ClientActivityTracker(props, uaDetector);
        EndpointEnumerationDetector detector = new EndpointEnumerationDetector(props, tracker);

        var record = tracker.recordRequest("5.5.5.5", "/does-not-exist", "GET", "Mozilla/5.0");
        record.setStatus(404);

        DetectionResult result = detector.evaluate(requestFor("/does-not-exist"));
        assertFalse(result.triggered(), "A single 404 must never be classified as enumeration");
    }

    @Test
    void doesNotTriggerOnNormalBrowsingWithFewFailures() {
        CalixSentryProperties props = lowThresholdProperties();
        ScannerUserAgentDetector uaDetector = new ScannerUserAgentDetector(props);
        ClientActivityTracker tracker = new ClientActivityTracker(props, uaDetector);
        EndpointEnumerationDetector detector = new EndpointEnumerationDetector(props, tracker);

        String[] normalPaths = {"/", "/products", "/products/1", "/cart", "/checkout", "/about", "/contact", "/does-not-exist", "/help", "/faq", "/terms"};
        DetectionResult last = DetectionResult.none();
        for (String path : normalPaths) {
            var record = tracker.recordRequest("6.6.6.6", path, "GET", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            record.setStatus(path.equals("/does-not-exist") ? 404 : 200);
            last = detector.evaluate(requestFor(path));
        }

        assertFalse(last.triggered(), "Normal browsing (11 unique pages, one incidental 404) must not trigger enumeration detection");
    }
}
