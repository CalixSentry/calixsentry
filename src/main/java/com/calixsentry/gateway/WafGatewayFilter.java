package com.calixsentry.gateway;

import com.calixsentry.accesslist.AccessListService;
import com.calixsentry.activity.AccessRecorder;
import com.calixsentry.blocking.BlockEntry;
import com.calixsentry.blocking.BlockStore;
import com.calixsentry.config.CalixSentryProperties;
import com.calixsentry.detection.DetectionResult;
import com.calixsentry.detection.Detector;
import com.calixsentry.detection.behavioral.ClientActivityTracker;
import com.calixsentry.events.SecurityEvent;
import com.calixsentry.events.SecurityEventPublisher;
import com.calixsentry.pipeline.ClientIdentifier;
import com.calixsentry.pipeline.RequestContext;
import com.calixsentry.pipeline.RequestNormalizer;
import com.calixsentry.policy.Action;
import com.calixsentry.policy.PolicyDecision;
import com.calixsentry.policy.PolicyEngine;
import com.calixsentry.ratelimit.RateLimiter;
import com.calixsentry.scoring.ThreatAssessment;
import com.calixsentry.scoring.ThreatScoringEngine;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The Gateway: implements the request processing pipeline from spec section 10.
 *
 * <pre>
 * Incoming Request
 *   -> dashboard / API / actuator (management port only) skip proxying entirely
 *   -> anything else that lands on the management port is rejected (404)
 *   -> Request Normalization      (RequestNormalizer)
 *   -> Client Identification      (ClientIdentifier)
 *   -> Denylist / Active Block check   -> immediate BLOCK
 *   -> Allowlist check             -> bypasses rate limit + detection-driven actions
 *   -> Rate Analysis (mechanical)  (RateLimiter)               -> immediate RATE_LIMIT
 *   -> Signature Detection + Behavioral Analysis (all Detector beans)
 *   -> Threat Scoring              (ThreatScoringEngine)
 *   -> Policy Evaluation           (PolicyEngine)
 *   -> Action: ALLOW forwards to backend; TEMPORARY_BLOCK short-circuits with 403
 *   -> Security Event / Access record / Metrics
 * </pre>
 *
 * This class is an ORCHESTRATOR ONLY - it contains no detection logic and no
 * policy logic itself, delegating to the single-responsibility collaborators.
 */
@Component
public class WafGatewayFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(WafGatewayFilter.class);
    private static final int MAX_LOGGED_URI = 500;

    private final CalixSentryProperties properties;
    private final ManagementRouting routing;
    private final RequestNormalizer normalizer;
    private final ClientIdentifier clientIdentifier;
    private final List<Detector> detectors;
    private final ThreatScoringEngine scoringEngine;
    private final PolicyEngine policyEngine;
    private final BlockStore blockStore;
    private final AccessListService accessListService;
    private final RateLimiter rateLimiter;
    private final ClientActivityTracker activityTracker;
    private final SecurityEventPublisher eventPublisher;
    private final ProxyForwardingService proxyForwardingService;
    private final AccessRecorder accessRecorder;

    public WafGatewayFilter(CalixSentryProperties properties, ManagementRouting routing,
                             RequestNormalizer normalizer, ClientIdentifier clientIdentifier,
                             List<Detector> detectors, ThreatScoringEngine scoringEngine,
                             PolicyEngine policyEngine, BlockStore blockStore,
                             AccessListService accessListService, RateLimiter rateLimiter,
                             ClientActivityTracker activityTracker, SecurityEventPublisher eventPublisher,
                             ProxyForwardingService proxyForwardingService, AccessRecorder accessRecorder) {
        this.properties = properties;
        this.routing = routing;
        this.normalizer = normalizer;
        this.clientIdentifier = clientIdentifier;
        this.detectors = detectors;
        this.scoringEngine = scoringEngine;
        this.policyEngine = policyEngine;
        this.blockStore = blockStore;
        this.accessListService = accessListService;
        this.rateLimiter = rateLimiter;
        this.activityTracker = activityTracker;
        this.eventPublisher = eventPublisher;
        this.proxyForwardingService = proxyForwardingService;
        this.accessRecorder = accessRecorder;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return routing.servesManagement(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // The management port serves ONLY the dashboard/API/actuator - it is not a proxy.
        if (routing.isOnManagementPort(request)) {
            response.setStatus(404);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Not found on the management port\"}");
            return;
        }

        eventPublisher.countRequest();

        String clientIp = clientIdentifier.resolve(request);
        String method = request.getMethod();
        String fullUri = clip(fullUri(request));
        String lowerPath = request.getRequestURI().toLowerCase(Locale.ROOT);
        String userAgent = request.getHeader("User-Agent");

        // 1. Denylist - equivalent to a standing manual block.
        if (accessListService.isDenylisted(clientIp)) {
            respondBlocked(response, 403, "Client is on the denylist");
            publishSimpleEvent(clientIp, request, fullUri, 403, "BLOCK", "CS-DENYLIST-001",
                    List.of("Client IP matches an administrator-configured denylist entry"));
            accessRecorder.record(clientIp, method, fullUri, lowerPath, userAgent, 403, "BLOCK", 100, null, "CS-DENYLIST-001");
            return;
        }

        boolean allowlisted = accessListService.isAllowlisted(clientIp);

        // 2. Active block (temporary or permanent), unless explicitly allowlisted.
        if (!allowlisted) {
            var activeBlock = blockStore.findActiveBlock(clientIp);
            if (activeBlock.isPresent()) {
                BlockEntry entry = activeBlock.get();
                if (entry.getExpiresAt() != null) {
                    long retryAfter = Math.max(0, entry.getExpiresAt().getEpochSecond() - System.currentTimeMillis() / 1000);
                    response.setHeader("Retry-After", String.valueOf(retryAfter));
                }
                String ruleId = entry.getRuleId() != null ? entry.getRuleId() : "CS-BLOCK-ACTIVE";
                respondBlocked(response, 403, "Client is currently blocked");
                publishSimpleEvent(clientIp, request, fullUri, 403, "BLOCK", ruleId,
                        List.of("Active " + entry.getType() + " block: " + entry.getReason()));
                accessRecorder.record(clientIp, method, fullUri, lowerPath, userAgent, 403, "BLOCK", 100, null, ruleId);
                return;
            }
        }

        // 3. Mechanical rate limiting - independent of protection mode (spec section 16).
        if (!allowlisted && !rateLimiter.tryAcquire(clientIp)) {
            eventPublisher.countRateLimited();
            response.setHeader("Retry-After", String.valueOf(properties.getRateLimit().getWindow().toSeconds()));
            respondBlocked(response, 429, "Rate limit exceeded");
            publishSimpleEvent(clientIp, request, fullUri, 429, "RATE_LIMIT", "CS-RATE-LIMIT-001",
                    List.of("Exceeded configured rate limit of " + properties.getRateLimit().getRequestsPerWindow()
                            + " requests per " + properties.getRateLimit().getWindow()));
            accessRecorder.record(clientIp, method, fullUri, lowerPath, userAgent, 429, "RATE_LIMIT", 0, "HTTP_ABUSE", "CS-RATE-LIMIT-001");
            return;
        }

        // 4. Read body (bounded) and normalize.
        byte[] body = readBodyBounded(request, response);
        if (body == null) return; // response already written (413)

        RequestContext context = normalizer.normalize(request, clientIp, body);

        // Record this request in the client's behavioral window BEFORE we know the
        // backend's response; the status is filled in once we have it.
        var activityRecord = activityTracker.recordRequest(clientIp, context.getNormalizedPath(), context.getMethod(), context.getUserAgent());

        // 5. Detection - every enabled detector. A detector that throws fails SAFE (no detection).
        List<DetectionResult> results = new ArrayList<>();
        for (Detector detector : detectors) {
            try {
                results.add(detector.evaluate(context));
            } catch (Exception e) {
                log.error("Detector {} threw an exception - failing safe (treated as no detection)", detector.ruleId(), e);
            }
        }

        // 6. Threat scoring.
        ThreatAssessment assessment = scoringEngine.assess(results);
        String category = assessment.isClean() ? null : assessment.dominantCategory().name();
        String ruleId = assessment.isClean() ? null : dominantRuleId(assessment);

        // 7. Policy decision (allowlisted clients are still scanned and logged, never blocked).
        PolicyDecision decision = allowlisted ? PolicyDecision.allow() : policyEngine.decide(assessment);

        if (decision.action() == Action.TEMPORARY_BLOCK) {
            Duration duration = decision.blockDuration() != null
                    ? decision.blockDuration()
                    : properties.getTemporaryBlock().getDefaultDuration();
            String reason = assessment.dominantCategory() + ": " + String.join("; ", assessment.reasons());
            blockStore.blockTemporary(clientIp, reason, ruleId, duration, "SYSTEM");

            respondBlocked(response, 403, "Automatically blocked: " + assessment.dominantCategory());
            publishEvent(context, null, assessment, decision, duration);
            accessRecorder.record(clientIp, method, fullUri, context.getNormalizedPath(), userAgent,
                    403, Action.TEMPORARY_BLOCK.name(), assessment.score(), category, ruleId);
            return;
        }

        // 8. Forward to backend and return its response UNCHANGED (spec section 23).
        BackendResponse backendResponse;
        try {
            backendResponse = proxyForwardingService.forward(
                    context.getMethod(), context.getRawUri(), context.getHeaders(), body, clientIp);
        } catch (java.net.http.HttpTimeoutException e) {
            activityRecord.setStatus(504);
            recordForwardFailure(context, clientIp, fullUri, userAgent, 504, decision, assessment, category, ruleId);
            respondBlocked(response, 504, "Backend did not respond in time");
            return;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            log.warn("Failed to reach backend for {} {}: {}", context.getMethod(), context.getRawUri(), e.getMessage());
            activityRecord.setStatus(502);
            recordForwardFailure(context, clientIp, fullUri, userAgent, 502, decision, assessment, category, ruleId);
            respondBlocked(response, 502, "Backend unavailable");
            return;
        }

        int status = backendResponse.status();
        activityRecord.setStatus(status);
        if (!assessment.isClean()) {
            publishEvent(context, status, assessment, decision, null);
        }
        accessRecorder.record(clientIp, method, fullUri, context.getNormalizedPath(), userAgent,
                status, decision.action().name(), assessment.score(), category, ruleId);

        // Writing to the client can fail if the visitor disconnected - that is NOT a backend failure.
        copyBackendResponse(backendResponse, response);
    }

    private void recordForwardFailure(RequestContext context, String clientIp, String fullUri, String userAgent,
                                       int status, PolicyDecision decision, ThreatAssessment assessment,
                                       String category, String ruleId) {
        if (!assessment.isClean()) {
            publishEvent(context, status, assessment, decision, null);
        }
        accessRecorder.record(clientIp, context.getMethod(), fullUri, context.getNormalizedPath(), userAgent,
                status, decision.action().name(), assessment.score(), category, ruleId);
    }

    private String fullUri(HttpServletRequest request) {
        String query = request.getQueryString();
        return query == null || query.isEmpty() ? request.getRequestURI() : request.getRequestURI() + "?" + query;
    }

    private static String clip(String value) {
        if (value == null) return "";
        return value.length() <= MAX_LOGGED_URI ? value : value.substring(0, MAX_LOGGED_URI);
    }

    private String dominantRuleId(ThreatAssessment assessment) {
        return assessment.triggeredDetections().stream()
                .max((a, b) -> Integer.compare(a.totalScoreContribution(), b.totalScoreContribution()))
                .map(DetectionResult::ruleId)
                .orElse("CS-POLICY-AUTOBLOCK");
    }

    private byte[] readBodyBounded(HttpServletRequest request, HttpServletResponse response) throws IOException {
        int max = properties.getBackend().getMaxRequestBytes();
        try (var in = request.getInputStream()) {
            byte[] buffer = new byte[8192];
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int read;
            int total = 0;
            while ((read = in.read(buffer)) != -1) {
                total += read;
                if (total > max) {
                    response.setStatus(413);
                    response.getWriter().write("Request body exceeds the configured maximum size.");
                    return null;
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private void copyBackendResponse(BackendResponse backendResponse, HttpServletResponse response) throws IOException {
        response.setStatus(backendResponse.status());
        for (var entry : backendResponse.headers().entrySet()) {
            String name = entry.getKey();
            if (name == null) continue; // HttpClient can include a null-key pseudo-header for the status line
            String lower = name.toLowerCase(Locale.ROOT);
            if (lower.equals("connection") || lower.equals("transfer-encoding") || lower.equals("content-length")) continue;
            for (String value : entry.getValue()) {
                response.addHeader(name, value);
            }
        }
        response.getOutputStream().write(backendResponse.body());
    }

    private void respondBlocked(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write("{\"blocked\":true,\"message\":\"" + message.replace("\"", "'") + "\"}");
    }

    private void publishSimpleEvent(String clientIp, HttpServletRequest request, String fullUri, int status,
                                     String action, String ruleId, List<String> reasons) {
        boolean rateLimit = action.equals("RATE_LIMIT");
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp(clientIp)
                .method(request.getMethod())
                .uri(fullUri)
                .userAgent(request.getHeader("User-Agent"))
                .status(status)
                .category(rateLimit ? "HTTP_ABUSE" : "MALICIOUS_FILE_ACCESS")
                .severity(rateLimit ? "MEDIUM" : "HIGH")
                .threatScore(rateLimit ? 0 : 100)
                .action(action)
                .recommendedAction(action)
                .ruleId(ruleId)
                .reasons(reasons)
                .build();
        eventPublisher.publish(event);
    }

    private void publishEvent(RequestContext context, Integer status, ThreatAssessment assessment,
                               PolicyDecision decision, Duration blockDuration) {
        SecurityEvent event = SecurityEvent.builder()
                .sourceIp(context.getClientIp())
                .method(context.getMethod())
                .uri(clip(context.getRawTarget()))
                .userAgent(context.getUserAgent())
                .status(status)
                .category(assessment.dominantCategory().name())
                .severity(assessment.level().name())
                .threatScore(assessment.score())
                .action(decision.action().name())
                .recommendedAction(decision.recommendedAction().name())
                .ruleId(dominantRuleId(assessment))
                .reasons(assessment.reasons())
                .blockDurationSeconds(blockDuration != null ? blockDuration.toSeconds() : null)
                .build();
        eventPublisher.publish(event);
    }
}
