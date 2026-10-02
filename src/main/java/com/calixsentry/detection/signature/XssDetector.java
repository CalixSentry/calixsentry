package com.calixsentry.detection.signature;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.*;
import com.calixsentry.pipeline.RequestContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * CS-XSS-001 - Cross-Site Scripting Detection (signature-based, reflected/stored
 * indicators visible at the gateway). Catches script tags, event-handler
 * injection, javascript: URIs, and common encoded bypass attempts.
 */
@Component
public class XssDetector implements Detector {

    private final CalixSentryProperties properties;

    private static final List<Pattern> PATTERNS = List.of(
            Pattern.compile("(?i)<\\s*script\\b"),
            Pattern.compile("(?i)on(error|load|click|mouseover|focus)\\s*="),
            Pattern.compile("(?i)javascript\\s*:"),
            Pattern.compile("(?i)<\\s*iframe\\b"),
            Pattern.compile("(?i)<\\s*img[^>]+onerror"),
            Pattern.compile("(?i)document\\.cookie"),
            Pattern.compile("(?i)<\\s*svg[^>]*onload"),
            Pattern.compile("(?i)String\\.fromCharCode"),
            Pattern.compile("(?i)%3Cscript"),
            Pattern.compile("(?i)eval\\s*\\(")
    );

    public XssDetector(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override public String ruleId() { return "CS-XSS-001"; }
    @Override public String name() { return "Cross-Site Scripting Detection"; }
    @Override public DetectionCategory category() { return DetectionCategory.CROSS_SITE_SCRIPTING; }
    @Override public Severity severity() { return Severity.HIGH; }
    @Override public String description() {
        return "Matches common reflected/stored XSS indicators: script tags, inline event "
                + "handlers, javascript: URIs, DOM sinks, and common encoded bypass attempts.";
    }
    @Override public boolean isEnabled() { return properties.getDetection().isXss(); }

    @Override
    public DetectionResult evaluate(RequestContext context) {
        if (!isEnabled()) return DetectionResult.none();

        String surface = context.getInspectionSurface();
        List<String> matched = new ArrayList<>();
        for (Pattern p : PATTERNS) {
            if (p.matcher(surface).find()) {
                matched.add(p.pattern());
            }
        }
        if (matched.isEmpty()) return DetectionResult.none();

        int weight = properties.getScoring().getWeightKnownSignature();
        List<Finding> findings = new ArrayList<>();
        findings.add(new Finding("XSS pattern matched (" + matched.size() + " indicator(s))", weight));
        return new DetectionResult(ruleId(), category(), true, findings);
    }
}
