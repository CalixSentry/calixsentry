package com.calixsentry.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Root configuration object bound from calixsentry.yml / environment variables.
 *
 * Every tunable that affects detection sensitivity, scoring weights, and
 * policy behaviour lives here rather than being hard-coded in detectors, so
 * an administrator can change behaviour without recompiling.
 */
@ConfigurationProperties(prefix = "calixsentry")
public class CalixSentryProperties {

    /** Public-facing gateway (reverse proxy) settings. */
    private final Server server = new Server();

    /** Where legitimate traffic is forwarded once policy says ALLOW. */
    private final Backend backend = new Backend();

    /** Protection mode + automatic blocking master switch. */
    private final Protection protection = new Protection();

    /** Per-detector enable/disable flags. */
    private final Detection detection = new Detection();

    /** Threat scoring weights and severity bands. */
    private final Scoring scoring = new Scoring();

    /** Temporary block durations and persistence. */
    private final TemporaryBlock temporaryBlock = new TemporaryBlock();

    /** Rate limiting. */
    private final RateLimit rateLimit = new RateLimit();

    /** Security event sinks. */
    private final Events events = new Events();

    /** Elasticsearch sink (optional). */
    private final Elasticsearch elasticsearch = new Elasticsearch();

    /** Management API / dashboard auth. */
    private final Management management = new Management();

    /** Authentication for the management dashboard/API - the equivalent of Elastic's xpack.security. */
    private final Security security = new Security();

    public Server getServer() { return server; }
    public Backend getBackend() { return backend; }
    public Protection getProtection() { return protection; }
    public Detection getDetection() { return detection; }
    public Scoring getScoring() { return scoring; }
    public TemporaryBlock getTemporaryBlock() { return temporaryBlock; }
    public RateLimit getRateLimit() { return rateLimit; }
    public Events getEvents() { return events; }
    public Elasticsearch getElasticsearch() { return elasticsearch; }
    public Management getManagement() { return management; }
    public Security getSecurity() { return security; }

    public static class Server {
        /** Interface the public gateway listens on. */
        private String host = "0.0.0.0";
        /** Public gateway port (what your visitors hit). Never hard-code this in code - always read from here. */
        private int port = 8080;
        /**
         * Dedicated MANAGEMENT port for the dashboard, management API and actuator.
         * When > 0, those endpoints are served ONLY on this port (on a second connector)
         * and are NOT reachable on the public gateway port. Set to 0 to disable the split
         * and serve everything on the single public port (not recommended for production).
         */
        private int managementPort = 9400;
        /** Interface the management port binds to. Default is loopback-only. */
        private String managementBindAddress = "127.0.0.1";

        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        public int getManagementPort() { return managementPort; }
        public void setManagementPort(int managementPort) { this.managementPort = managementPort; }
        public String getManagementBindAddress() { return managementBindAddress; }
        public void setManagementBindAddress(String managementBindAddress) { this.managementBindAddress = managementBindAddress; }
    }

    public static class Backend {
        /** Base URL of the customer application this gateway protects. */
        private String baseUrl = "http://localhost:8081";
        private Duration connectTimeout = Duration.ofSeconds(5);
        private Duration readTimeout = Duration.ofSeconds(30);
        private int maxRequestBytes = 10 * 1024 * 1024; // 10 MB - abuse/resource-exhaustion guard

        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public Duration getConnectTimeout() { return connectTimeout; }
        public void setConnectTimeout(Duration connectTimeout) { this.connectTimeout = connectTimeout; }
        public Duration getReadTimeout() { return readTimeout; }
        public void setReadTimeout(Duration readTimeout) { this.readTimeout = readTimeout; }
        public int getMaxRequestBytes() { return maxRequestBytes; }
        public void setMaxRequestBytes(int maxRequestBytes) { this.maxRequestBytes = maxRequestBytes; }
    }

    public static class Protection {
        /**
         * SAFE DEFAULT: MONITOR. Never ships enabled for blocking. See
         * spec section 18 - this must be explicit, opt-in.
         */
        private String mode = "MONITOR"; // MONITOR | ALERT | MANUAL | AUTOMATIC
        private boolean automaticBlocking = false;
        private int alertThreshold = 30;   // score at/above which ALERT mode raises an alert
        private int automaticBlockThreshold = 80; // score at/above which AUTOMATIC mode may block
        private Duration automaticBlockDuration = Duration.ofMinutes(10);

        public String getMode() { return mode; }
        public void setMode(String mode) { this.mode = mode; }
        public boolean isAutomaticBlocking() { return automaticBlocking; }
        public void setAutomaticBlocking(boolean automaticBlocking) { this.automaticBlocking = automaticBlocking; }
        public int getAlertThreshold() { return alertThreshold; }
        public void setAlertThreshold(int alertThreshold) { this.alertThreshold = alertThreshold; }
        public int getAutomaticBlockThreshold() { return automaticBlockThreshold; }
        public void setAutomaticBlockThreshold(int automaticBlockThreshold) { this.automaticBlockThreshold = automaticBlockThreshold; }
        public Duration getAutomaticBlockDuration() { return automaticBlockDuration; }
        public void setAutomaticBlockDuration(Duration automaticBlockDuration) { this.automaticBlockDuration = automaticBlockDuration; }
    }

    public static class Detection {
        private boolean botScanning = true;
        private boolean endpointEnumeration = true;
        private boolean sqlInjection = true;
        private boolean xss = true;
        private boolean pathTraversal = true;
        private boolean commandInjection = true;
        private boolean sensitivePaths = true;
        private boolean scannerUserAgents = true;

        // Behavioral thresholds - tunable, see docs/DETECTION.md
        private int enumerationWindowSeconds = 300; // 5 minutes
        private int enumerationUniquePathThreshold = 50;
        private double enumerationNotFoundRatioThreshold = 0.90;
        private int enumerationMinRequests = 15; // don't judge on tiny samples
        private int sensitivePathHitsThreshold = 3;
        private long minRequestIntervalMillisForBurst = 150;
        private double veryHighRequestsPerSecondThreshold = 5.0;

        public boolean isBotScanning() { return botScanning; }
        public void setBotScanning(boolean botScanning) { this.botScanning = botScanning; }
        public boolean isEndpointEnumeration() { return endpointEnumeration; }
        public void setEndpointEnumeration(boolean endpointEnumeration) { this.endpointEnumeration = endpointEnumeration; }
        public boolean isSqlInjection() { return sqlInjection; }
        public void setSqlInjection(boolean sqlInjection) { this.sqlInjection = sqlInjection; }
        public boolean isXss() { return xss; }
        public void setXss(boolean xss) { this.xss = xss; }
        public boolean isPathTraversal() { return pathTraversal; }
        public void setPathTraversal(boolean pathTraversal) { this.pathTraversal = pathTraversal; }
        public boolean isCommandInjection() { return commandInjection; }
        public void setCommandInjection(boolean commandInjection) { this.commandInjection = commandInjection; }
        public boolean isSensitivePaths() { return sensitivePaths; }
        public void setSensitivePaths(boolean sensitivePaths) { this.sensitivePaths = sensitivePaths; }
        public boolean isScannerUserAgents() { return scannerUserAgents; }
        public void setScannerUserAgents(boolean scannerUserAgents) { this.scannerUserAgents = scannerUserAgents; }
        public int getEnumerationWindowSeconds() { return enumerationWindowSeconds; }
        public void setEnumerationWindowSeconds(int enumerationWindowSeconds) { this.enumerationWindowSeconds = enumerationWindowSeconds; }
        public int getEnumerationUniquePathThreshold() { return enumerationUniquePathThreshold; }
        public void setEnumerationUniquePathThreshold(int enumerationUniquePathThreshold) { this.enumerationUniquePathThreshold = enumerationUniquePathThreshold; }
        public double getEnumerationNotFoundRatioThreshold() { return enumerationNotFoundRatioThreshold; }
        public void setEnumerationNotFoundRatioThreshold(double enumerationNotFoundRatioThreshold) { this.enumerationNotFoundRatioThreshold = enumerationNotFoundRatioThreshold; }
        public int getEnumerationMinRequests() { return enumerationMinRequests; }
        public void setEnumerationMinRequests(int enumerationMinRequests) { this.enumerationMinRequests = enumerationMinRequests; }
        public int getSensitivePathHitsThreshold() { return sensitivePathHitsThreshold; }
        public void setSensitivePathHitsThreshold(int sensitivePathHitsThreshold) { this.sensitivePathHitsThreshold = sensitivePathHitsThreshold; }
        public long getMinRequestIntervalMillisForBurst() { return minRequestIntervalMillisForBurst; }
        public void setMinRequestIntervalMillisForBurst(long minRequestIntervalMillisForBurst) { this.minRequestIntervalMillisForBurst = minRequestIntervalMillisForBurst; }
        public double getVeryHighRequestsPerSecondThreshold() { return veryHighRequestsPerSecondThreshold; }
        public void setVeryHighRequestsPerSecondThreshold(double v) { this.veryHighRequestsPerSecondThreshold = v; }
    }

    public static class Scoring {
        private int weightEndpointEnumeration = 30;
        private int weightHighRequestRate = 20;
        private int weightHighNotFoundRatio = 15;
        private int weightSensitivePaths = 15;
        private int weightSuspiciousUserAgent = 10;
        private int weightKnownSignature = 30; // SQLi/XSS/traversal/cmd-injection hit
        private int weightBurstBehavior = 10;

        private int lowMax = 29;
        private int mediumMax = 59;
        private int highMax = 79; // 80-100 = CRITICAL

        public int getWeightEndpointEnumeration() { return weightEndpointEnumeration; }
        public void setWeightEndpointEnumeration(int v) { this.weightEndpointEnumeration = v; }
        public int getWeightHighRequestRate() { return weightHighRequestRate; }
        public void setWeightHighRequestRate(int v) { this.weightHighRequestRate = v; }
        public int getWeightHighNotFoundRatio() { return weightHighNotFoundRatio; }
        public void setWeightHighNotFoundRatio(int v) { this.weightHighNotFoundRatio = v; }
        public int getWeightSensitivePaths() { return weightSensitivePaths; }
        public void setWeightSensitivePaths(int v) { this.weightSensitivePaths = v; }
        public int getWeightSuspiciousUserAgent() { return weightSuspiciousUserAgent; }
        public void setWeightSuspiciousUserAgent(int v) { this.weightSuspiciousUserAgent = v; }
        public int getWeightKnownSignature() { return weightKnownSignature; }
        public void setWeightKnownSignature(int v) { this.weightKnownSignature = v; }
        public int getWeightBurstBehavior() { return weightBurstBehavior; }
        public void setWeightBurstBehavior(int v) { this.weightBurstBehavior = v; }
        public int getLowMax() { return lowMax; }
        public void setLowMax(int v) { this.lowMax = v; }
        public int getMediumMax() { return mediumMax; }
        public void setMediumMax(int v) { this.mediumMax = v; }
        public int getHighMax() { return highMax; }
        public void setHighMax(int v) { this.highMax = v; }
    }

    public static class TemporaryBlock {
        private Duration defaultDuration = Duration.ofMinutes(10);
        private List<Long> allowedDurationsSeconds = new ArrayList<>(List.of(
                300L, 600L, 1800L, 3600L, 21600L, 86400L
        ));
        private String persistenceFile = "/data/calixsentry/blocks.json";

        public Duration getDefaultDuration() { return defaultDuration; }
        public void setDefaultDuration(Duration defaultDuration) { this.defaultDuration = defaultDuration; }
        public List<Long> getAllowedDurationsSeconds() { return allowedDurationsSeconds; }
        public void setAllowedDurationsSeconds(List<Long> allowedDurationsSeconds) { this.allowedDurationsSeconds = allowedDurationsSeconds; }
        public String getPersistenceFile() { return persistenceFile; }
        public void setPersistenceFile(String persistenceFile) { this.persistenceFile = persistenceFile; }
    }

    public static class RateLimit {
        private boolean enabled = true;
        private int requestsPerWindow = 100;
        private Duration window = Duration.ofSeconds(60);
        private int burst = 20;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getRequestsPerWindow() { return requestsPerWindow; }
        public void setRequestsPerWindow(int requestsPerWindow) { this.requestsPerWindow = requestsPerWindow; }
        public Duration getWindow() { return window; }
        public void setWindow(Duration window) { this.window = window; }
        public int getBurst() { return burst; }
        public void setBurst(int burst) { this.burst = burst; }
    }

    public static class Events {
        private boolean fileSinkEnabled = true;
        private boolean webhookEnabled = false;
        private String webhookUrl = "";
        private int inMemoryRetention = 5000; // most recent N events kept for the live dashboard view

        /** Directory holding the daily log files (calixsentry-events-YYYY-MM-DD.jsonl, calixsentry-access-YYYY-MM-DD.jsonl). */
        private String logDir = "/data/calixsentry/logs";
        /** Time zone that decides where one "day" ends and the next begins (e.g. Asia/Kolkata). */
        private String timezone = "UTC";
        /** Delete security-event log files older than this many days. 0 = keep forever. */
        private int retentionDays = 90;
        /** Also write EVERY proxied request to a daily access log (needed for full per-IP history). */
        private boolean accessLogEnabled = true;
        /** Delete access log files older than this many days. 0 = keep forever. */
        private int accessLogRetentionDays = 14;

        /** Max distinct client IPs kept in memory for the live per-IP view. */
        private int ipTrackerMaxIps = 10000;
        /** Max recent requests remembered per IP. */
        private int ipTrailPerIp = 300;
        /** Forget IPs not seen for this many hours. */
        private int ipRetentionHours = 24;

        public boolean isFileSinkEnabled() { return fileSinkEnabled; }
        public void setFileSinkEnabled(boolean fileSinkEnabled) { this.fileSinkEnabled = fileSinkEnabled; }
        public boolean isWebhookEnabled() { return webhookEnabled; }
        public void setWebhookEnabled(boolean webhookEnabled) { this.webhookEnabled = webhookEnabled; }
        public String getWebhookUrl() { return webhookUrl; }
        public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }
        public int getInMemoryRetention() { return inMemoryRetention; }
        public void setInMemoryRetention(int inMemoryRetention) { this.inMemoryRetention = inMemoryRetention; }
        public String getLogDir() { return logDir; }
        public void setLogDir(String logDir) { this.logDir = logDir; }
        public String getTimezone() { return timezone; }
        public void setTimezone(String timezone) { this.timezone = timezone; }
        public int getRetentionDays() { return retentionDays; }
        public void setRetentionDays(int retentionDays) { this.retentionDays = retentionDays; }
        public boolean isAccessLogEnabled() { return accessLogEnabled; }
        public void setAccessLogEnabled(boolean accessLogEnabled) { this.accessLogEnabled = accessLogEnabled; }
        public int getAccessLogRetentionDays() { return accessLogRetentionDays; }
        public void setAccessLogRetentionDays(int accessLogRetentionDays) { this.accessLogRetentionDays = accessLogRetentionDays; }
        public int getIpTrackerMaxIps() { return ipTrackerMaxIps; }
        public void setIpTrackerMaxIps(int ipTrackerMaxIps) { this.ipTrackerMaxIps = ipTrackerMaxIps; }
        public int getIpTrailPerIp() { return ipTrailPerIp; }
        public void setIpTrailPerIp(int ipTrailPerIp) { this.ipTrailPerIp = ipTrailPerIp; }
        public int getIpRetentionHours() { return ipRetentionHours; }
        public void setIpRetentionHours(int ipRetentionHours) { this.ipRetentionHours = ipRetentionHours; }
    }

    public static class Elasticsearch {
        /** Optional by design - see spec section 29 / 11. NOT IMPLEMENTED in MVP; see docs/ROADMAP.md. */
        private boolean enabled = false;
        private String url = "";
        private String indexPrefix = "calixsentry-events";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getIndexPrefix() { return indexPrefix; }
        public void setIndexPrefix(String indexPrefix) { this.indexPrefix = indexPrefix; }
    }

    public static class Security {
        /**
         * Master switch for dashboard/API authentication - mirrors xpack.security.enabled.
         * SAFE DEFAULT: true. Only set to false for local-only evaluation; CalixSentry will
         * log a loud warning at startup if security is disabled.
         */
        private boolean enabled = true;
        /** Admin username. */
        private String adminUsername = "admin";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getAdminUsername() { return adminUsername; }
        public void setAdminUsername(String adminUsername) { this.adminUsername = adminUsername; }
    }

    public static class Management {
        /** Path prefix reserved for the dashboard + API, excluded from proxying. */
        private String basePath = "/calixsentry";
        private List<String> trustedProxyIps = new ArrayList<>();

        public String getBasePath() { return basePath; }
        public void setBasePath(String basePath) { this.basePath = basePath; }
        public List<String> getTrustedProxyIps() { return trustedProxyIps; }
        public void setTrustedProxyIps(List<String> trustedProxyIps) { this.trustedProxyIps = trustedProxyIps; }
    }
}
