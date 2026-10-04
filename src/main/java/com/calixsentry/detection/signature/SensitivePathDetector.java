package com.calixsentry.detection.signature;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.*;
import com.calixsentry.pipeline.RequestContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * CS-SENSITIVE-001 - Sensitive Path Access Detection.
 *
 * A single hit here is a WEAK signal on its own (a legitimate user could
 * fat-finger a URL). Its real power is as an input to
 * {@link com.calixsentry.detection.behavioral.EndpointEnumerationDetector},
 * which looks at how MANY distinct sensitive paths a client has probed over
 * a time window. This detector still reports a small direct score so a
 * single high-value hit (e.g. /.git/config) isn't completely invisible.
 */
@Component
public class SensitivePathDetector implements Detector {

    private final CalixSentryProperties properties;

    public static final Set<String> SENSITIVE_PATHS = Set.of(
            "/.env", "/.git/config", "/.git/head", "/wp-admin", "/wp-login.php",
            "/phpinfo.php", "/config.php", "/backup.zip", "/backup.sql", "/server-status",
            "/server-info", "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa",
            "/.htaccess", "/.htpasswd", "/web.config", "/wp-config.php",
            "/administrator", "/admin.php", "/phpmyadmin", "/actuator/env",
            "/actuator/heapdump", "/debug", "/.svn/entries", "/.idea/workspace.xml",
            "/docker-compose.yml", "/.dockerenv", "/composer.json", "/package.json",
            "/.well-known/security.txt"
    );

    public SensitivePathDetector(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override public String ruleId() { return "CS-SENSITIVE-001"; }
    @Override public String name() { return "Sensitive Path Access Detection"; }
    @Override public DetectionCategory category() { return DetectionCategory.SENSITIVE_PATH_ACCESS; }
    @Override public Severity severity() { return Severity.MEDIUM; }
    @Override public String description() {
        return "Flags requests to well-known sensitive files/paths (secrets, VCS metadata, "
                + "admin panels, backup files). A single hit is weak evidence; repeated hits "
                + "across many sensitive paths strongly indicate automated scanning - see "
                + "EndpointEnumerationDetector.";
    }
    @Override public boolean isEnabled() { return properties.getDetection().isSensitivePaths(); }

    public static boolean isSensitive(String normalizedPath) {
        return SENSITIVE_PATHS.contains(normalizedPath);
    }

    @Override
    public DetectionResult evaluate(RequestContext context) {
        if (!isEnabled()) return DetectionResult.none();
        if (!isSensitive(context.getNormalizedPath())) return DetectionResult.none();

        List<Finding> findings = new ArrayList<>();
        // Intentionally a small fraction of the "sensitive paths" scoring weight for a
        // single hit; the behavioral detector applies the full weight for a pattern.
        int weight = Math.max(1, properties.getScoring().getWeightSensitivePaths() / 3);
        findings.add(new Finding("Requested known-sensitive path: " + context.getNormalizedPath(), weight));
        return new DetectionResult(ruleId(), category(), true, findings);
    }
}
