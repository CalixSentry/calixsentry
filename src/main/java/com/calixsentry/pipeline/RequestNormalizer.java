package com.calixsentry.pipeline;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.time.Instant;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns a raw HttpServletRequest into a RequestContext.
 *
 * Normalization matters for security, not just convenience: attackers use
 * double-encoding, mixed case, Unicode tricks, and redundant slashes/dot
 * segments to smuggle payloads past naive string matching. We decode and
 * canonicalize a *copy* of the path used only for inspection - the original
 * rawUri is preserved and is what actually gets forwarded to the backend, so
 * normalization never changes application behaviour, only detection.
 */
@Component
public class RequestNormalizer {

    /** Cap how much of the body we ever hold in memory for inspection - resource-exhaustion guard. */
    private static final int MAX_BODY_PREVIEW_BYTES = 65536;

    public RequestContext normalize(HttpServletRequest request, String clientIp, byte[] bodyBytes) {
        String rawUri = request.getRequestURI();
        String normalizedPath = canonicalize(rawUri);

        Map<String, String> headers = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        if (names != null) {
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                headers.put(name.toLowerCase(), request.getHeader(name));
            }
        }

        long bodySize = bodyBytes == null ? 0 : bodyBytes.length;
        String bodyPreview = "";
        if (bodyBytes != null && bodyBytes.length > 0) {
            int len = Math.min(bodyBytes.length, MAX_BODY_PREVIEW_BYTES);
            bodyPreview = new String(bodyBytes, 0, len, StandardCharsets.UTF_8);
        }

        return new RequestContext(
                clientIp,
                request.getMethod(),
                rawUri,
                normalizedPath,
                request.getQueryString(),
                Collections.unmodifiableMap(headers),
                request.getHeader("User-Agent"),
                bodySize,
                bodyPreview,
                Instant.now()
        );
    }

    /**
     * Best-effort canonical form used ONLY for detection:
     *  1. URL-decode (handles %2e%2e%2f style encoded traversal)
     *  2. Unicode NFKC normalize (collapses homoglyph/full-width tricks)
     *  3. Collapse duplicate slashes
     *  4. Lower-case (path matching against known sensitive paths is
     *     case-insensitive on most targets; content forwarded is untouched)
     */
    String canonicalize(String uri) {
        if (uri == null) return "/";
        String decoded = safeDecode(uri);
        // Decode a second time in case of double-encoding, but cap iterations
        // to avoid ReDoS/loop abuse from pathological input.
        String doubleDecoded = safeDecode(decoded);
        String chosen = doubleDecoded.contains("..") ? doubleDecoded : decoded;

        String normalized = Normalizer.normalize(chosen, Normalizer.Form.NFKC);
        normalized = normalized.replaceAll("/{2,}", "/");
        return normalized.toLowerCase();
    }

    private String safeDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }
}
