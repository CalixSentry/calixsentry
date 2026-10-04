package com.calixsentry.detection.signature;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.*;
import com.calixsentry.pipeline.RequestContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * CS-TRAVERSAL-001 - Path Traversal Detection.
 *
 * Checks the RAW uri as well as the normalized/decoded path (see
 * RequestNormalizer), so double-encoded (%252e%252e%252f) and mixed
 * encoded/unencoded traversal attempts are both caught, not just the naive
 * literal "../" case.
 */
@Component
public class PathTraversalDetector implements Detector {

    private final CalixSentryProperties properties;

    private static final List<Pattern> PATTERNS = List.of(
            Pattern.compile("\\.\\./"),
            Pattern.compile("\\.\\.\\\\"),
            Pattern.compile("(?i)%2e%2e(%2f|%5c|/)"),
            Pattern.compile("(?i)%252e%252e"),
            Pattern.compile("(?i)\\.\\.%2f"),
            Pattern.compile("(?i)/etc/passwd"),
            Pattern.compile("(?i)/proc/self/environ"),
            Pattern.compile("(?i)win\\.ini|boot\\.ini"),
            Pattern.compile("(?i)\\.\\.;/") // legacy Tomcat path-parameter bypass trick
    );

    public PathTraversalDetector(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override public String ruleId() { return "CS-TRAVERSAL-001"; }
    @Override public String name() { return "Path Traversal Detection"; }
    @Override public DetectionCategory category() { return DetectionCategory.PATH_TRAVERSAL; }
    @Override public Severity severity() { return Severity.HIGH; }
    @Override public String description() {
        return "Matches directory traversal sequences in raw and decoded (including "
                + "double-encoded) request paths, plus common sensitive-file targets.";
    }
    @Override public boolean isEnabled() { return properties.getDetection().isPathTraversal(); }

    @Override
    public DetectionResult evaluate(RequestContext context) {
        if (!isEnabled()) return DetectionResult.none();

        String combined = context.getRawUri() + " " + context.getInspectionSurface();
        List<String> matched = new ArrayList<>();
        for (Pattern p : PATTERNS) {
            if (p.matcher(combined).find()) {
                matched.add(p.pattern());
            }
        }
        if (matched.isEmpty()) return DetectionResult.none();

        int weight = properties.getScoring().getWeightKnownSignature();
        List<Finding> findings = new ArrayList<>();
        findings.add(new Finding("Path traversal pattern matched (" + matched.size() + " indicator(s))", weight));
        return new DetectionResult(ruleId(), category(), true, findings);
    }
}
