package com.calixsentry.detection.signature;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.*;
import com.calixsentry.pipeline.RequestContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** CS-CMDI-001 - OS Command Injection Detection (signature-based). */
@Component
public class CommandInjectionDetector implements Detector {

    private final CalixSentryProperties properties;

    private static final List<Pattern> PATTERNS = List.of(
            Pattern.compile("(?i);\\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\\b"),
            Pattern.compile("(?i)\\|\\s*(cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\\b"),
            Pattern.compile("\\$\\([^)]{1,80}\\)"),
            Pattern.compile("`[^`]{1,80}`"),
            Pattern.compile("(?i)&&\\s*(cat|ls|whoami|id|uname)\\b"),
            Pattern.compile("(?i)\\bnc\\s+-e\\b"),
            Pattern.compile("(?i)/bin/(ba)?sh")
    );

    public CommandInjectionDetector(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override public String ruleId() { return "CS-CMDI-001"; }
    @Override public String name() { return "OS Command Injection Detection"; }
    @Override public DetectionCategory category() { return DetectionCategory.COMMAND_INJECTION; }
    @Override public Severity severity() { return Severity.CRITICAL; }
    @Override public String description() {
        return "Matches shell metacharacter chaining and common command-injection idioms "
                + "(command substitution, backticks, chained shell commands) in request input.";
    }
    @Override public boolean isEnabled() { return properties.getDetection().isCommandInjection(); }

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
        findings.add(new Finding("Command injection pattern matched (" + matched.size() + " indicator(s))", weight));
        return new DetectionResult(ruleId(), category(), true, findings);
    }
}
