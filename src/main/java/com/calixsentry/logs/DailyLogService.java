package com.calixsentry.logs;

import com.calixsentry.config.CalixSentryProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Daily, date-named log files (JSON Lines):
 *
 *   calixsentry-events-2026-09-28.jsonl   security events
 *   calixsentry-access-2026-09-28.jsonl   every proxied request
 *
 * A new file starts automatically when the day changes (in the configured
 * time zone). Files older than the configured retention are deleted; today's
 * file is never touched. Days are always addressed by a parsed LocalDate, so
 * a caller can never smuggle a path into a file name (no path traversal).
 */
@Component
public class DailyLogService {

    private static final Logger log = LoggerFactory.getLogger(DailyLogService.class);

    /** One available day: ISO date + file size. */
    public record DayInfo(String date, long sizeBytes) { }

    private static final class OpenFile {
        LocalDate date;
        BufferedWriter writer;
    }

    private final CalixSentryProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Object writeLock = new Object();
    private final Map<LogKind, OpenFile> open = new EnumMap<>(LogKind.class);

    public DailyLogService(CalixSentryProperties properties) {
        this.properties = properties;
    }

    public ZoneId zone() {
        try {
            return ZoneId.of(properties.getEvents().getTimezone());
        } catch (Exception e) {
            return ZoneOffset.UTC; // a bad zone name must never stop logging
        }
    }

    public LocalDate today() {
        return LocalDate.now(zone());
    }

    private Path dir() {
        return Path.of(properties.getEvents().getLogDir());
    }

    public Path pathFor(LogKind kind, LocalDate date) {
        return dir().resolve(kind.filePrefix() + "-" + date + ".jsonl");
    }

    /** Appends one JSON line to today's file for this kind. Never throws. */
    public void append(LogKind kind, String jsonLine) {
        synchronized (writeLock) {
            OpenFile file = open.computeIfAbsent(kind, k -> new OpenFile());
            try {
                LocalDate today = today();
                if (file.writer == null || !today.equals(file.date)) {
                    closeQuietly(file);
                    Path path = pathFor(kind, today);
                    Files.createDirectories(path.getParent());
                    file.writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                    file.date = today;
                }
                file.writer.write(jsonLine);
                file.writer.write('\n');
                file.writer.flush();
            } catch (IOException e) {
                log.error("Could not write {} log: {}", kind, e.getMessage());
                closeQuietly(file); // reopen on the next write
            }
        }
    }

    /** Days that have a log file for this kind, newest first. */
    public List<DayInfo> listDays(LogKind kind) {
        Path dir = dir();
        if (!Files.isDirectory(dir)) return List.of();
        Pattern pattern = Pattern.compile("^" + Pattern.quote(kind.filePrefix()) + "-(\\d{4}-\\d{2}-\\d{2})\\.jsonl$");
        try (Stream<Path> files = Files.list(dir)) {
            return files
                    .map(path -> toDayInfo(pattern, path))
                    .filter(Objects::nonNull)
                    .sorted(Comparator.comparing(DayInfo::date).reversed())
                    .toList();
        } catch (IOException e) {
            log.warn("Could not list {} logs: {}", kind, e.getMessage());
            return List.of();
        }
    }

    private DayInfo toDayInfo(Pattern pattern, Path path) {
        Matcher m = pattern.matcher(path.getFileName().toString());
        if (!m.matches()) return null;
        try {
            LocalDate.parse(m.group(1));
            return new DayInfo(m.group(1), Files.size(path));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Reads one day's file and returns the MOST RECENT {@code limit} lines that pass the filter,
     * newest first. Streams the file line by line, so a large day never has to fit in memory.
     */
    public List<JsonNode> search(LogKind kind, LocalDate date, Predicate<JsonNode> filter, int limit) {
        Path path = pathFor(kind, date);
        if (!Files.isRegularFile(path)) return List.of();

        ArrayDeque<JsonNode> window = new ArrayDeque<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;
                JsonNode node;
                try {
                    node = mapper.readTree(line);
                } catch (Exception e) {
                    continue; // skip a corrupt/partial line, keep reading
                }
                if (node == null || !filter.test(node)) continue;
                window.addLast(node);
                if (window.size() > limit) window.pollFirst();
            }
        } catch (IOException e) {
            log.warn("Problem reading {}: {}", path, e.getMessage());
        }
        List<JsonNode> result = new ArrayList<>(window);
        Collections.reverse(result);
        return result;
    }

    /** Deletes files older than the configured retention. Runs every 6 hours. */
    @Scheduled(fixedDelay = 21_600_000L, initialDelay = 60_000L)
    public void purgeExpired() {
        purge(LogKind.EVENTS, properties.getEvents().getRetentionDays());
        purge(LogKind.ACCESS, properties.getEvents().getAccessLogRetentionDays());
    }

    void purge(LogKind kind, int retentionDays) {
        if (retentionDays <= 0) return; // 0 = keep forever
        LocalDate cutoff = today().minusDays(retentionDays);
        for (DayInfo day : listDays(kind)) {
            LocalDate date = LocalDate.parse(day.date());
            if (date.isBefore(cutoff)) {
                try {
                    Files.deleteIfExists(pathFor(kind, date));
                    log.info("Deleted expired {} log {} (older than {} days)", kind, day.date(), retentionDays);
                } catch (IOException e) {
                    log.warn("Could not delete {} log {}: {}", kind, day.date(), e.getMessage());
                }
            }
        }
    }

    @PreDestroy
    public void close() {
        synchronized (writeLock) {
            for (OpenFile file : open.values()) closeQuietly(file);
        }
    }

    private void closeQuietly(OpenFile file) {
        if (file.writer != null) {
            try {
                file.writer.close();
            } catch (IOException ignored) {
                // nothing useful to do
            }
            file.writer = null;
        }
    }
}
