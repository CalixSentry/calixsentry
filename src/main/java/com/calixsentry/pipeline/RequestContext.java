package com.calixsentry.pipeline;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

/**
 * Immutable, normalized view of an inbound HTTP request, produced by
 * {@link RequestNormalizer}. Every detector and the policy engine operate on
 * this object rather than the raw HttpServletRequest, so detection logic is
 * decoupled from the servlet API and independently testable.
 */
public final class RequestContext {

    private final String clientIp;
    private final String method;
    private final String rawUri;
    private final String normalizedPath;
    private final String queryString;
    private final Map<String, String> headers;
    private final String userAgent;
    private final long bodySize;
    private final String bodyPreview; // truncated, text-decoded body used only for signature scanning
    private final Instant receivedAt;

    public RequestContext(String clientIp, String method, String rawUri, String normalizedPath,
                           String queryString, Map<String, String> headers, String userAgent,
                           long bodySize, String bodyPreview, Instant receivedAt) {
        this.clientIp = clientIp;
        this.method = method;
        this.rawUri = rawUri;
        this.normalizedPath = normalizedPath;
        this.queryString = queryString == null ? "" : queryString;
        this.headers = Collections.unmodifiableMap(headers);
        this.userAgent = userAgent == null ? "" : userAgent;
        this.bodySize = bodySize;
        this.bodyPreview = bodyPreview == null ? "" : bodyPreview;
        this.receivedAt = receivedAt;
    }

    public String getClientIp() { return clientIp; }
    public String getMethod() { return method; }
    public String getRawUri() { return rawUri; }
    public String getNormalizedPath() { return normalizedPath; }
    public String getQueryString() { return queryString; }
    public Map<String, String> getHeaders() { return headers; }
    public String getUserAgent() { return userAgent; }
    public long getBodySize() { return bodySize; }
    public String getBodyPreview() { return bodyPreview; }
    public Instant getReceivedAt() { return receivedAt; }

    public String getFullTarget() {
        return queryString.isEmpty() ? normalizedPath : normalizedPath + "?" + queryString;
    }

    /** The URI exactly as received, including the raw query string - what an admin needs to see in an event. */
    public String getRawTarget() {
        return queryString.isEmpty() ? rawUri : rawUri + "?" + queryString;
    }

    /** Combined surface used by signature detectors: path + query + body preview. */
    public String getInspectionSurface() {
        return normalizedPath + " " + queryString + " " + bodyPreview;
    }
}
