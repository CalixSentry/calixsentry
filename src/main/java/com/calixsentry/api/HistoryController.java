package com.calixsentry.api;

import com.calixsentry.logs.DailyLogService;
import com.calixsentry.logs.LogKind;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;

/**
 * {basePath}/api/history - look back at the daily log files.
 *
 *   GET  /history/{events|access}/days                 which days have a file
 *   GET  /history/{events|access}/{yyyy-MM-dd}         search one day (filters below)
 *   GET  /history/{events|access}/{yyyy-MM-dd}/download the raw .jsonl file
 *
 * The date is parsed into a LocalDate and the file name is built from that, so there
 * is no way to point this at any other file on disk.
 */
@RestController
@RequestMapping("${calixsentry.management.base-path}/api/history")
public class HistoryController {

    private static final int MAX_LIMIT = 5000;

    private final DailyLogService dailyLogs;

    public HistoryController(DailyLogService dailyLogs) {
        this.dailyLogs = dailyLogs;
    }

    @GetMapping("/{kind}/days")
    public ResponseEntity<?> days(@PathVariable String kind) {
        LogKind logKind = LogKind.fromUrlName(kind);
        if (logKind == null) return badKind();
        return ResponseEntity.ok(dailyLogs.listDays(logKind));
    }

    @GetMapping("/{kind}/{date}")
    public ResponseEntity<?> day(@PathVariable String kind, @PathVariable String date,
                                  @RequestParam(defaultValue = "500") int limit,
                                  @RequestParam(required = false) String ip,
                                  @RequestParam(required = false) String category,
                                  @RequestParam(required = false) String severity,
                                  @RequestParam(required = false) String action,
                                  @RequestParam(required = false) String q) {
        LogKind logKind = LogKind.fromUrlName(kind);
        if (logKind == null) return badKind();
        LocalDate parsed = parseDate(date);
        if (parsed == null) return badDate();

        List<JsonNode> rows = dailyLogs.search(logKind, parsed,
                filter(ip, category, severity, action, q), Math.max(1, Math.min(limit, MAX_LIMIT)));
        return ResponseEntity.ok(rows);
    }

    @GetMapping("/{kind}/{date}/download")
    public ResponseEntity<Resource> download(@PathVariable String kind, @PathVariable String date) {
        LogKind logKind = LogKind.fromUrlName(kind);
        LocalDate parsed = parseDate(date);
        if (logKind == null || parsed == null) return ResponseEntity.badRequest().build();

        Path file = dailyLogs.pathFor(logKind, parsed);
        if (!Files.isRegularFile(file)) return ResponseEntity.notFound().build();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getFileName() + "\"")
                .contentType(MediaType.parseMediaType("application/x-ndjson"))
                .body(new FileSystemResource(file));
    }

    private static LocalDate parseDate(String date) {
        try {
            return LocalDate.parse(date);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static ResponseEntity<?> badKind() {
        return ResponseEntity.badRequest().body(Map.of("error", "Log kind must be 'events' or 'access'."));
    }

    private static ResponseEntity<?> badDate() {
        return ResponseEntity.badRequest().body(Map.of("error", "Date must look like 2026-09-28."));
    }

    /** Same filter works for both log kinds: fields that don't exist simply don't match. */
    private static Predicate<JsonNode> filter(String ip, String category, String severity, String action, String q) {
        String qLower = q == null ? "" : q.trim().toLowerCase(Locale.ROOT);
        return node -> {
            if (notBlank(ip) && !text(node, "sourceIp").equalsIgnoreCase(ip.trim())) return false;
            if (notBlank(category) && !text(node, "category").equalsIgnoreCase(category.trim())) return false;
            if (notBlank(severity) && !text(node, "severity").equalsIgnoreCase(severity.trim())) return false;
            if (notBlank(action) && !text(node, "action").equalsIgnoreCase(action.trim())) return false;
            if (!qLower.isEmpty()) {
                String haystack = (text(node, "uri") + " " + text(node, "sourceIp") + " "
                        + text(node, "userAgent") + " " + text(node, "reasons")).toLowerCase(Locale.ROOT);
                if (node.has("reasons") && node.get("reasons").isArray()) {
                    StringBuilder sb = new StringBuilder(haystack);
                    node.get("reasons").forEach(r -> sb.append(' ').append(r.asText("").toLowerCase(Locale.ROOT)));
                    haystack = sb.toString();
                }
                if (!haystack.contains(qLower)) return false;
            }
            return true;
        };
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? "" : value.asText("");
    }
}
