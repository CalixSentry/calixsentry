package com.calixsentry.activity;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.signature.SensitivePathDetector;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Live, per-client-IP activity picture: every request each IP made (not only the
 * ones that triggered a detection), so an administrator can open one IP and see
 * exactly what it looked for - which paths, how often, what came back.
 *
 * Memory is bounded on purpose (max IPs, max recent requests per IP, max distinct
 * paths per IP, idle expiry), so a flood of many IPs or many paths cannot exhaust
 * the JVM. It is in-memory: it does not survive a restart. Long-term history lives
 * in the daily access log files (see DailyLogService).
 */
@Component
public class IpActivityStore {

    public record TrailEntry(Instant timestamp, String method, String uri, Integer status, String action, int score) { }

    public record PathStat(String path, long count, Integer lastStatus, boolean sensitive) { }

    public record IpSummary(String ip, Instant firstSeen, Instant lastSeen, long totalRequests,
                            long blockedRequests, long notFoundRequests, int distinctPaths, int maxThreatScore) { }

    public record IpProfile(IpSummary summary, Map<String, Long> statusCounts,
                            List<PathStat> paths, List<TrailEntry> recent) { }

    private static final int MAX_PATHS_PER_IP = 1000;
    private static final int MAX_URI_LENGTH = 300;

    private static final class PathCounter {
        long count;
        Integer lastStatus;
    }

    private static final class IpState {
        final String ip;
        final Instant firstSeen;
        volatile Instant lastSeen;
        long total;
        long blocked;
        long notFound;
        int maxScore;
        final Map<Integer, Long> statusCounts = new TreeMap<>();
        final LinkedHashMap<String, PathCounter> paths = new LinkedHashMap<>();
        final ArrayDeque<TrailEntry> trail = new ArrayDeque<>();

        IpState(String ip) {
            this.ip = ip;
            this.firstSeen = Instant.now();
            this.lastSeen = this.firstSeen;
        }
    }

    private final CalixSentryProperties properties;
    private final ConcurrentHashMap<String, IpState> states = new ConcurrentHashMap<>();

    public IpActivityStore(CalixSentryProperties properties) {
        this.properties = properties;
    }

    public void record(String ip, String method, String uri, String path,
                       Integer status, String action, int score) {
        if (ip == null || ip.isBlank()) return;
        var cfg = properties.getEvents();

        IpState state = states.get(ip);
        if (state == null) {
            // Hard ceiling: refuse to track brand-new IPs if we are far past the limit
            // (the periodic sweep trims back down to the configured maximum).
            if (states.size() >= cfg.getIpTrackerMaxIps() * 2L) return;
            state = states.computeIfAbsent(ip, IpState::new);
        }

        Instant now = Instant.now();
        synchronized (state) {
            state.lastSeen = now;
            state.total++;
            if (status != null) {
                state.statusCounts.merge(status, 1L, Long::sum);
                if (status == 404) state.notFound++;
            }
            if (isBlockingAction(action)) state.blocked++;
            state.maxScore = Math.max(state.maxScore, score);

            if (path != null) {
                PathCounter counter = state.paths.get(path);
                if (counter == null && state.paths.size() < MAX_PATHS_PER_IP) {
                    counter = new PathCounter();
                    state.paths.put(path, counter);
                }
                if (counter != null) {
                    counter.count++;
                    if (status != null) counter.lastStatus = status;
                }
            }

            state.trail.addLast(new TrailEntry(now, method, clip(uri), status, action, score));
            while (state.trail.size() > cfg.getIpTrailPerIp()) {
                state.trail.pollFirst();
            }
        }
    }

    private static boolean isBlockingAction(String action) {
        return "BLOCK".equals(action) || "TEMPORARY_BLOCK".equals(action) || "RATE_LIMIT".equals(action);
    }

    private static String clip(String value) {
        if (value == null) return "";
        return value.length() <= MAX_URI_LENGTH ? value : value.substring(0, MAX_URI_LENGTH);
    }

    private IpSummary summarize(IpState s) {
        synchronized (s) {
            return new IpSummary(s.ip, s.firstSeen, s.lastSeen, s.total, s.blocked,
                    s.notFound, s.paths.size(), s.maxScore);
        }
    }

    /** Summaries of tracked IPs, most recently active first. Optional substring match on the IP. */
    public List<IpSummary> summaries(String query, int limit) {
        String q = query == null ? "" : query.trim();
        return states.values().stream()
                .map(this::summarize)
                .filter(s -> q.isEmpty() || s.ip().contains(q))
                .sorted(Comparator.comparing(IpSummary::lastSeen).reversed())
                .limit(Math.max(1, limit))
                .toList();
    }

    public Optional<IpProfile> profile(String ip) {
        IpState s = states.get(ip);
        if (s == null) return Optional.empty();
        synchronized (s) {
            List<PathStat> paths = new ArrayList<>();
            for (Map.Entry<String, PathCounter> e : s.paths.entrySet()) {
                paths.add(new PathStat(e.getKey(), e.getValue().count, e.getValue().lastStatus,
                        SensitivePathDetector.isSensitive(e.getKey())));
            }
            Map<String, Long> statusCounts = new LinkedHashMap<>();
            s.statusCounts.forEach((code, n) -> statusCounts.put(String.valueOf(code), n));

            List<TrailEntry> recent = new ArrayList<>(s.trail);
            Collections.reverse(recent); // newest first

            return Optional.of(new IpProfile(summarize(s), statusCounts, paths, recent));
        }
    }

    public int trackedIpCount() {
        return states.size();
    }

    /** Drops idle IPs, then trims to the configured maximum (oldest activity first). */
    @Scheduled(fixedDelay = 60_000)
    public void sweep() {
        var cfg = properties.getEvents();
        Instant cutoff = Instant.now().minus(Duration.ofHours(cfg.getIpRetentionHours()));
        states.entrySet().removeIf(e -> e.getValue().lastSeen.isBefore(cutoff));

        int max = cfg.getIpTrackerMaxIps();
        if (states.size() > max) {
            List<IpState> oldestFirst = states.values().stream()
                    .sorted(Comparator.comparing((IpState s) -> s.lastSeen))
                    .toList();
            int excess = states.size() - max;
            for (int i = 0; i < excess && i < oldestFirst.size(); i++) {
                states.remove(oldestFirst.get(i).ip);
            }
        }
    }
}
