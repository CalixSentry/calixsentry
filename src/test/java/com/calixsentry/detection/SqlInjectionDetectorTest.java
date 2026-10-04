package com.calixsentry.detection;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.signature.SqlInjectionDetector;
import com.calixsentry.pipeline.RequestContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SqlInjectionDetectorTest {

    private final CalixSentryProperties props = new CalixSentryProperties();
    private final SqlInjectionDetector detector = new SqlInjectionDetector(props);

    private RequestContext ctx(String path, String query, String body) {
        return new RequestContext("1.2.3.4", "GET", path, path, query, Map.of(), "test-agent", 0, body, Instant.now());
    }

    @Test
    void detectsUnionSelect() {
        DetectionResult r = detector.evaluate(ctx("/products", "id=1 UNION SELECT username,password FROM users", null));
        assertTrue(r.triggered());
        assertEquals("CS-SQLI-001", r.ruleId());
    }

    @Test
    void detectsTautology() {
        DetectionResult r = detector.evaluate(ctx("/login", "user=admin' OR '1'='1", null));
        assertTrue(r.triggered());
    }

    @Test
    void detectsInBody() {
        DetectionResult r = detector.evaluate(ctx("/api/search", "", "q=1; DROP TABLE users;--"));
        assertTrue(r.triggered());
    }

    @Test
    void allowsNormalTraffic() {
        DetectionResult r = detector.evaluate(ctx("/products", "category=shoes&sort=price", null));
        assertFalse(r.triggered());
    }

    @Test
    void disabledDetectorNeverTriggers() {
        props.getDetection().setSqlInjection(false);
        DetectionResult r = detector.evaluate(ctx("/login", "user=admin' OR '1'='1", null));
        assertFalse(r.triggered());
    }
}
