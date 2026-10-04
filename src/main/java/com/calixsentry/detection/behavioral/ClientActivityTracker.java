package com.calixsentry.detection.behavioral;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.signature.SensitivePathDetector;
import com.calixsentry.detection.signature.ScannerUserAgentDetector;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * Maintains a rolling, per-client (IP) window of recent request activity, and
 * computes derived statistics (unique paths, 404 ratio, request rate, etc.)
 * used by behavioral detectors such as {@link EndpointEnumerationDetector}.
 *
 * This is the piece that lets CalixSentry recognize "GET /admin, GET /.env,
 * GET /wp-admin, GET /random-path-1 ..." as a PATTERN even though each
 * individual request may be a harmless 404.
 *
 * MVP storage: in-memory, per-JVM. This does not survive restarts and does
 * not share state across multiple gateway instances - noted as a scaling
 * limitation in docs/ROADMAP.md (future: shared store e.g. Redis).
 */
@Component
public class ClientActivityTracker {

    private final CalixSentryProperties properties;
    private final ScannerUserAgentDetector scannerUserAgentDetector;

    private final ConcurrentHashMap<String, ConcurrentLinkedDeque<RequestRecord>> windows = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    public ClientActivityTracker(CalixSentryProperties properties, ScannerUserAgentDetector scannerUserAgentDetector) {
        this.properties = properties;
        this.scannerUserAgentDetector = scannerUserAgentDetector;
    }

    public RequestRecord recordRequest(String clientIp, String path, String method, String userAgent) {
        RequestRecord record = new RequestRecord(Instant.now(), path, method, userAgent);
        windows.computeIfAbsent(clientIp, k -> new ConcurrentLinkedDeque<>()).addLast(record);
        pruneExpired(clientIp);
        return record;
    }

    private void pruneExpired(String clientIp) {
        ConcurrentLinkedDeque<RequestRecord> window = windows.get(clientIp);
        if (window == null) return;
        Instant cutoff = Instant.now().minusSeconds(properties.getDetection().getEnumerationWindowSeconds());
        RequestRecord head;
        while ((head = window.peekFirst()) != null && head.timestamp.isBefore(cutoff)) {
            window.pollFirst();
        }
    }

    public ClientStats getStats(String clientIp) {
        pruneExpired(clientIp);
        ConcurrentLinkedDeque<RequestRecord> window = windows.getOrDefault(clientIp, new ConcurrentLinkedDeque<>());
        var snapshot = window.stream().collect(Collectors.toList());

        int total = snapshot.size();
        Set<String> uniquePaths = snapshot.stream().map(r -> r.path).collect(Collectors.toSet());
        int notFound = (int) snapshot.stream().filter(r -> r.status == 404).count();
        int forbidden = (int) snapshot.stream().filter(r -> r.status == 401 || r.status == 403).count();
        int serverError = (int) snapshot.stream().filter(r -> r.status >= 500 && r.status < 600).count();
        int sensitiveHits = (int) snapshot.stream().filter(r -> SensitivePathDetector.isSensitive(r.path)).count();
        Set<String> methods = snapshot.stream().map(r -> r.method).collect(Collectors.toSet());
        boolean scannerUa = snapshot.stream().anyMatch(r -> scannerUserAgentDetector.isScannerUserAgent(r.userAgent));

        double avgIntervalMillis = 0.0;
        double requestsPerSecond = 0.0;
        if (total >= 2) {
            long firstMillis = snapshot.get(0).timestamp.toEpochMilli();
            long lastMillis = snapshot.get(total - 1).timestamp.toEpochMilli();
            long spanMillis = Math.max(1, lastMillis - firstMillis);
            avgIntervalMillis = (double) spanMillis / (total - 1);
            requestsPerSecond = total / (spanMillis / 1000.0);
        }

        return new ClientStats(total, uniquePaths.size(), notFound, forbidden, serverError,
                sensitiveHits, avgIntervalMillis, requestsPerSecond, methods.size(), scannerUa);
    }

    /** Periodic sweep so idle clients' windows don't grow unbounded in memory. */
    @Scheduled(fixedDelay = 60_000)
    public void sweep() {
        for (String ip : windows.keySet()) {
            pruneExpired(ip);
            ConcurrentLinkedDeque<RequestRecord> window = windows.get(ip);
            if (window != null && window.isEmpty()) {
                windows.remove(ip, window);
            }
        }
    }

    int trackedClientCount() {
        return windows.size();
    }
}
