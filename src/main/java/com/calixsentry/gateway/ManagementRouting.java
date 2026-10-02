package com.calixsentry.gateway;

import com.calixsentry.config.CalixSentryProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Decides which requests belong to the dashboard / management API and which are
 * public traffic to be inspected and proxied.
 *
 * With a management port configured (default 9400), the dashboard, API and actuator
 * exist ONLY on that port. On the public port those same URLs are treated like any
 * other path: inspected and forwarded to the protected application - so the admin
 * interface is simply not there for the internet to find.
 *
 * With management-port = 0 the old single-port behaviour applies (everything on the
 * public port).
 */
@Component
public class ManagementRouting {

    private final CalixSentryProperties properties;

    public ManagementRouting(CalixSentryProperties properties) {
        this.properties = properties;
    }

    public boolean isSeparated() {
        return properties.getServer().getManagementPort() > 0;
    }

    /** True if this request arrived on the dedicated management connector. */
    public boolean isOnManagementPort(HttpServletRequest request) {
        return isSeparated() && request.getLocalPort() == properties.getServer().getManagementPort();
    }

    public boolean isManagementPath(String path) {
        String base = properties.getManagement().getBasePath();
        return path.equals(base) || path.startsWith(base + "/")
                || path.equals("/actuator") || path.startsWith("/actuator/");
    }

    /**
     * True if this request should skip the WAF proxy and be handled by the dashboard/API/actuator
     * (or the /health probe, which is deliberately available on both ports for load balancers).
     */
    public boolean servesManagement(HttpServletRequest request) {
        String path = request.getRequestURI();
        if ("/health".equals(path)) return true;
        if (!isManagementPath(path)) return false;
        return !isSeparated() || isOnManagementPort(request);
    }
}
