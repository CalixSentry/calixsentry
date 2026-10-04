package com.calixsentry.detection;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.signature.PathTraversalDetector;
import com.calixsentry.pipeline.RequestContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PathTraversalDetectorTest {
    private final CalixSentryProperties props = new CalixSentryProperties();
    private final PathTraversalDetector detector = new PathTraversalDetector(props);

    private RequestContext ctx(String rawUri, String normalizedPath) {
        return new RequestContext("1.2.3.4", "GET", rawUri, normalizedPath, "", Map.of(), "browser", 0, null, Instant.now());
    }

    @Test
    void detectsUnencodedTraversal() {
        assertTrue(detector.evaluate(ctx("/files/../../etc/passwd", "/files/../../etc/passwd")).triggered());
    }

    @Test
    void detectsEncodedTraversal() {
        assertTrue(detector.evaluate(ctx("/files/%2e%2e%2f%2e%2e%2fetc/passwd", "/files/../../etc/passwd")).triggered());
    }

    @Test
    void detectsDoubleEncodedTraversal() {
        assertTrue(detector.evaluate(ctx("/files/%252e%252e%252f", "/files/../")).triggered());
    }

    @Test
    void allowsNormalPath() {
        assertFalse(detector.evaluate(ctx("/files/report-2026.pdf", "/files/report-2026.pdf")).triggered());
    }
}
