package com.calixsentry.pipeline;

import com.calixsentry.config.CalixSentryProperties;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

/**
 * Resolves the "client identity" used for rate limiting, blocking, and
 * behavioral tracking - currently the source IP.
 *
 * SECURITY NOTE: X-Forwarded-For / X-Real-IP are client-controllable headers.
 * We only trust them when the direct TCP peer is in the configured
 * trustedProxyIps list (i.e. our own edge load balancer). Even then the value
 * must look like a real IPv4/IPv6 literal: the result ends up in logs, the
 * dashboard and block lists, so arbitrary text is never accepted.
 */
@Component
public class ClientIdentifier {

    /** Only hex digits, dots and colons, up to the longest textual IPv6 form (45 chars). */
    private static final Pattern IP_LITERAL = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");

    private final CalixSentryProperties properties;

    public ClientIdentifier(CalixSentryProperties properties) {
        this.properties = properties;
    }

    public String resolve(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        if (properties.getManagement().getTrustedProxyIps().contains(remote)) {
            String forwardedFor = request.getHeader("X-Forwarded-For");
            if (forwardedFor != null && !forwardedFor.isBlank()) {
                // left-most entry is the original client per the usual convention
                String candidate = forwardedFor.split(",")[0].trim();
                if (IP_LITERAL.matcher(candidate).matches()) {
                    return candidate;
                }
            }
        }
        return remote;
    }
}
