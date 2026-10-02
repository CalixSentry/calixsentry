package com.calixsentry.events;

import com.calixsentry.config.CalixSentryProperties;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Central fan-out point for security events: pushes to every enabled
 * {@link EventSink} and retains the most recent N events in memory for the
 * dashboard/API (spec section 12: "real-time or near-real-time security
 * event view"). Also increments Micrometer counters (spec section 28).
 */
@Component
public class SecurityEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventPublisher.class);

    private final List<EventSink> sinks;
    private final CalixSentryProperties properties;
    private final ArrayDeque<SecurityEvent> recent = new ArrayDeque<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private final Counter requestsTotal;
    private final Counter detectionsTotal;
    private final Counter blocksTotal;
    private final Counter rateLimitsTotal;
    private final Counter securityEventsTotal;

    public SecurityEventPublisher(List<EventSink> sinks, CalixSentryProperties properties, MeterRegistry meterRegistry) {
        this.sinks = sinks;
        this.properties = properties;
        this.requestsTotal = Counter.builder("calixsentry_requests_total").register(meterRegistry);
        this.detectionsTotal = Counter.builder("calixsentry_detections_total").register(meterRegistry);
        this.blocksTotal = Counter.builder("calixsentry_blocks_total").register(meterRegistry);
        this.rateLimitsTotal = Counter.builder("calixsentry_rate_limits_total").register(meterRegistry);
        this.securityEventsTotal = Counter.builder("calixsentry_security_events_total").register(meterRegistry);
    }

    public void countRequest() {
        requestsTotal.increment();
    }

    public void countRateLimited() {
        rateLimitsTotal.increment();
    }

    public void publish(SecurityEvent event) {
        securityEventsTotal.increment();
        if (event.getThreatScore() > 0) {
            detectionsTotal.increment();
        }
        if ("TEMPORARY_BLOCK".equals(event.getAction()) || "BLOCK".equals(event.getAction())) {
            blocksTotal.increment();
        }

        lock.writeLock().lock();
        try {
            recent.addLast(event);
            while (recent.size() > properties.getEvents().getInMemoryRetention()) {
                recent.pollFirst();
            }
        } finally {
            lock.writeLock().unlock();
        }

        for (EventSink sink : sinks) {
            try {
                if (sink.isEnabled()) sink.publish(event);
            } catch (Exception e) {
                log.warn("Event sink '{}' threw while publishing: {}", sink.name(), e.getMessage());
            }
        }
    }

    public List<SecurityEvent> recentEvents(int limit) {
        lock.readLock().lock();
        try {
            return recent.stream()
                    .sorted(Comparator.comparing(SecurityEvent::getTimestamp).reversed())
                    .limit(limit)
                    .toList();
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<SecurityEvent> findById(String id) {
        lock.readLock().lock();
        try {
            return recent.stream().filter(e -> e.getId().equals(id)).findFirst();
        } finally {
            lock.readLock().unlock();
        }
    }

    public int totalRetained() {
        lock.readLock().lock();
        try {
            return recent.size();
        } finally {
            lock.readLock().unlock();
        }
    }
}
