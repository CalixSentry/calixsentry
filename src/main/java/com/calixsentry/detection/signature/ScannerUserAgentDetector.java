package com.calixsentry.detection.signature;

import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.*;
import com.calixsentry.pipeline.RequestContext;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * CS-BOT-UA-001 - Known Scanner/Tool User-Agent Detection.
 *
 * Deliberately low individual weight: User-Agent is trivially spoofable, so
 * this is a supporting signal, not a verdict. Its main value is nudging the
 * threat score when COMBINED with behavioral scanning evidence. An empty
 * User-Agent is also treated as mildly suspicious since real browsers always
 * send one.
 */
@Component
public class ScannerUserAgentDetector implements Detector {

    private final CalixSentryProperties properties;

    private static final Set<String> KNOWN_SCANNER_TOKENS = Set.of(
            "sqlmap", "nikto", "nmap", "nessus", "acunetix", "wpscan", "dirbuster",
            "gobuster", "ffuf", "masscan", "zgrab", "curl", "python-requests",
            "go-http-client", "libwww-perl", "havij", "burpsuite", "metasploit",
            "nuclei", "wfuzz", "feroxbuster"
    );

    public ScannerUserAgentDetector(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override public String ruleId() { return "CS-BOT-UA-001"; }
    @Override public String name() { return "Known Scanner/Tool User-Agent Detection"; }
    @Override public DetectionCategory category() { return DetectionCategory.SUSPICIOUS_USER_AGENT; }
    @Override public Severity severity() { return Severity.LOW; }
    @Override public String description() {
        return "Flags User-Agent strings associated with common scanning/exploitation "
                + "tooling (sqlmap, nikto, nmap, dirbuster, etc.) or a missing User-Agent. "
                + "Weak signal on its own - trivially spoofable - used mainly to corroborate "
                + "behavioral findings.";
    }
    @Override public boolean isEnabled() { return properties.getDetection().isScannerUserAgents(); }

    public boolean isScannerUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return true; // missing UA is itself a weak signal
        String lower = userAgent.toLowerCase(Locale.ROOT);
        for (String token : KNOWN_SCANNER_TOKENS) {
            if (lower.contains(token)) return true;
        }
        return false;
    }

    @Override
    public DetectionResult evaluate(RequestContext context) {
        if (!isEnabled()) return DetectionResult.none();
        if (!isScannerUserAgent(context.getUserAgent())) return DetectionResult.none();

        List<Finding> findings = new ArrayList<>();
        String label = context.getUserAgent() == null || context.getUserAgent().isBlank()
                ? "Missing User-Agent header"
                : "Suspicious/automated User-Agent: " + context.getUserAgent();
        findings.add(new Finding(label, properties.getScoring().getWeightSuspiciousUserAgent()));
        return new DetectionResult(ruleId(), category(), true, findings);
    }
}
