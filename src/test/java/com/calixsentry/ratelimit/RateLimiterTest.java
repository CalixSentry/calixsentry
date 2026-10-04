package com.calixsentry.ratelimit;

import com.calixsentry.config.CalixSentryProperties;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    @Test
    void allowsRequestsUpToConfiguredCapacityThenRejects() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getRateLimit().setEnabled(true);
        props.getRateLimit().setRequestsPerWindow(5);
        props.getRateLimit().setWindow(Duration.ofSeconds(60));
        props.getRateLimit().setBurst(0);

        RateLimiter limiter = new RateLimiter(props);
        String ip = "10.0.0.1";

        for (int i = 0; i < 5; i++) {
            assertTrue(limiter.tryAcquire(ip), "Request " + i + " should be within capacity");
        }
        assertFalse(limiter.tryAcquire(ip), "Request beyond capacity should be rejected");
    }

    @Test
    void disabledLimiterAlwaysAllows() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getRateLimit().setEnabled(false);
        RateLimiter limiter = new RateLimiter(props);

        for (int i = 0; i < 1000; i++) {
            assertTrue(limiter.tryAcquire("10.0.0.2"));
        }
    }

    @Test
    void distinctClientsHaveIndependentBuckets() {
        CalixSentryProperties props = new CalixSentryProperties();
        props.getRateLimit().setRequestsPerWindow(1);
        props.getRateLimit().setBurst(0);
        RateLimiter limiter = new RateLimiter(props);

        assertTrue(limiter.tryAcquire("10.0.0.3"));
        assertFalse(limiter.tryAcquire("10.0.0.3"));
        assertTrue(limiter.tryAcquire("10.0.0.4"), "A different client must not be affected by another client's limit");
    }
}
