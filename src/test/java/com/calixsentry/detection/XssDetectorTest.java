package com.calixsentry.detection;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.signature.XssDetector;
import com.calixsentry.pipeline.RequestContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class XssDetectorTest {
    private final CalixSentryProperties props = new CalixSentryProperties();
    private final XssDetector detector = new XssDetector(props);

    private RequestContext ctx(String query) {
        return new RequestContext("1.2.3.4", "GET", "/comment", "/comment", query, Map.of(), "browser", 0, null, Instant.now());
    }

    @Test
    void detectsScriptTag() {
        assertTrue(detector.evaluate(ctx("text=<script>alert(1)</script>")).triggered());
    }

    @Test
    void detectsEventHandlerInjection() {
        assertTrue(detector.evaluate(ctx("text=<img src=x onerror=alert(1)>")).triggered());
    }

    @Test
    void allowsPlainText() {
        assertFalse(detector.evaluate(ctx("text=hello world, this is < fine >")).triggered());
    }
}
