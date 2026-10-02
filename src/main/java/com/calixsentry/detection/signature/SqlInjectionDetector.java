package com.calixsentry.detection.signature;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.*;
import com.calixsentry.pipeline.RequestContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * CS-SQLI-001 - SQL Injection Detection (signature-based).
 *
 * IMPORTANT: this is a PATTERN detector, not a parser. It catches common,
 * well-known SQL injection idioms (tautologies, UNION-based extraction,
 * stacked queries, comment-based termination, common SQL error-based probes)
 * but - as required by the spec - this alone is NOT complete OWASP protection.
 * It is one input into the scoring engine, combined with behavioral signals.
 *
 * Patterns are deliberately simple (no nested quantifiers / catastrophic
 * backtracking shapes) to avoid ReDoS from attacker-controlled input, and the
 * inspection surface is capped in size upstream (see RequestNormalizer).
 */
@Component
public class SqlInjectionDetector implements Detector {

    private final CalixSentryProperties properties;

    private static final List<Pattern> PATTERNS = List.of(
            Pattern.compile("(?i)\\bunion\\b\\s+\\bselect\\b"),
            Pattern.compile("(?i)\\bor\\b\\s+1\\s*=\\s*1\\b"),
            Pattern.compile("(?i)\\band\\b\\s+1\\s*=\\s*1\\b"),
            Pattern.compile("(?i)'\\s*or\\s*'\\s*'\\s*=\\s*'"),
            Pattern.compile("(?i)\\bsleep\\s*\\(\\s*\\d+\\s*\\)"),
            Pattern.compile("(?i)\\bbenchmark\\s*\\("),
            Pattern.compile("(?i);\\s*(drop|delete|insert|update)\\b\\s+\\b(table|from|into)\\b"),
            Pattern.compile("(?i)\\bxp_cmdshell\\b"),
            Pattern.compile("(?i)information_schema\\.(tables|columns)"),
            Pattern.compile("--\\s*$"),
            Pattern.compile("(?i)/\\*.*?\\*/"),
            Pattern.compile("(?i)\\bwaitfor\\b\\s+\\bdelay\\b")
    );

    public SqlInjectionDetector(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override public String ruleId() { return "CS-SQLI-001"; }
    @Override public String name() { return "SQL Injection Detection"; }
    @Override public DetectionCategory category() { return DetectionCategory.SQL_INJECTION; }
    @Override public Severity severity() { return Severity.HIGH; }
    @Override public String description() {
        return "Matches common SQL injection idioms (tautologies, UNION SELECT, stacked "
                + "queries, time-based blind probes, comment termination) in the URI, query "
                + "string, and request body.";
    }
    @Override public boolean isEnabled() { return properties.getDetection().isSqlInjection(); }

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
        findings.add(new Finding("SQL injection pattern matched (" + matched.size() + " indicator(s))", weight));

        return new DetectionResult(ruleId(), category(), true, findings);
    }
}
