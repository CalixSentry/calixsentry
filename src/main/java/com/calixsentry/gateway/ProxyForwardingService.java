package com.calixsentry.gateway;

import com.calixsentry.config.CalixSentryProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The actual reverse-proxy leg: forwards a request that the policy engine
 * allowed through to the protected backend application, and returns its
 * response EXACTLY as received (status code, headers, body) - see spec
 * section 23: "Do not convert backend HTTP 404 responses into 502 errors."
 *
 * A 502/504 is only ever returned when CalixSentry itself cannot reach or
 * get a timely response from the backend - never as a mistranslation of a
 * legitimate backend status code.
 */
@Component
public class ProxyForwardingService {

    private static final Logger log = LoggerFactory.getLogger(ProxyForwardingService.class);

    /** Hop-by-hop headers that must never be blindly forwarded in either direction (RFC 7230 6.1). */
    private static final Set<String> HOP_BY_HOP = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"
    );

    /**
     * Client-supplied forwarding headers are never trusted or passed on: CalixSentry sets
     * X-Forwarded-For itself from the resolved client IP (see ClientIdentifier). Otherwise an
     * attacker could forge their apparent address to the backend application.
     */
    private static final Set<String> UNTRUSTED_FORWARDING_HEADERS = Set.of(
            "x-forwarded-for", "x-forwarded-by", "x-forwarded-host", "x-forwarded-proto",
            "x-real-ip", "forwarded"
    );

    private final CalixSentryProperties properties;
    private final HttpClient httpClient;

    public ProxyForwardingService(CalixSentryProperties properties) {
        this.properties = properties;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(properties.getBackend().getConnectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER) // redirects must be handled by the client, not silently rewritten
                .build();
    }

    public BackendResponse forward(String method, String rawUri, Map<String, String> requestHeaders,
                                    byte[] body, String clientIp) throws IOException, InterruptedException {

        URI target = URI.create(properties.getBackend().getBaseUrl()).resolve(rawUri);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(target)
                .timeout(properties.getBackend().getReadTimeout());

        for (var entry : requestHeaders.entrySet()) {
            String name = entry.getKey();
            String lowerName = name.toLowerCase(Locale.ROOT);
            if (HOP_BY_HOP.contains(lowerName) || UNTRUSTED_FORWARDING_HEADERS.contains(lowerName)) continue;
            try {
                builder.header(entry.getKey(), entry.getValue());
            } catch (IllegalArgumentException ignored) {
                // restricted header (e.g. "Host") - HttpClient manages these itself
            }
        }
        // Standard forwarding headers so the backend can see the true origin
        builder.header("X-Forwarded-For", clientIp);
        builder.header("X-Forwarded-By", "CalixSentry");

        HttpRequest.BodyPublisher bodyPublisher = (body == null || body.length == 0)
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body);

        builder.method(method.toUpperCase(Locale.ROOT), bodyPublisher);

        HttpResponse<byte[]> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());

        return new BackendResponse(response.statusCode(), response.headers().map(), response.body());
    }
}
