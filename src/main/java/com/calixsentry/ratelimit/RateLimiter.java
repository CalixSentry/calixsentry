package com.calixsentry.ratelimit;

import com.calixsentry.config.CalixSentryProperties;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Simple, mechanical per-IP token-bucket rate limiter (spec section 16).
 *
 * This is intentionally separate from the behavioral RateAnomalyDetector:
 * this class is a hard administrator-configured control (X requests per
 * window + burst allowance -> HTTP 429), not a scoring input. It runs
 * independent of the configured ProtectionMode, because rate limiting is an
 * explicit mechanism the administrator turned on, not an automatic response
 * to a detection.
 */
@Component
public class RateLimiter {

    private static final class Bucket {
        volatile double tokens;
        volatile long lastRefillNanos;
        Bucket(double tokens, long lastRefillNanos) {
            this.tokens = tokens;
            this.lastRefillNanos = lastRefillNanos;
        }
    }

    private final CalixSentryProperties properties;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimiter(CalixSentryProperties properties) {
        this.properties = properties;
    }

    /** Returns true if the request is allowed; false if it should receive HTTP 429. */
    public synchronized boolean tryAcquire(String clientIp) {
        var cfg = properties.getRateLimit();
        if (!cfg.isEnabled()) return true;

        double capacity = cfg.getRequestsPerWindow() + cfg.getBurst();
        double refillPerNano = cfg.getRequestsPerWindow() / (double) cfg.getWindow().toNanos();

        long now = System.nanoTime();
        Bucket bucket = buckets.computeIfAbsent(clientIp, k -> new Bucket(capacity, now));

        double elapsed = now - bucket.lastRefillNanos;
        double refill = elapsed * refillPerNano;
        bucket.tokens = Math.min(capacity, bucket.tokens + refill);
        bucket.lastRefillNanos = now;

        if (bucket.tokens >= 1.0) {
            bucket.tokens -= 1.0;
            return true;
        }
        return false;
    }

    /** Prevent unbounded memory growth from one-off/idle clients. */
    @Scheduled(fixedDelay = 300_000)
    public void sweep() {
        long cutoff = System.nanoTime() - properties.getRateLimit().getWindow().toNanos() * 10;
        buckets.entrySet().removeIf(e -> e.getValue().lastRefillNanos < cutoff);
    }

    int trackedClientCount() {
        return buckets.size();
    }
}
