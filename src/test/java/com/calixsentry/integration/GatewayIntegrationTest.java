package com.calixsentry.integration;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the FULL request pipeline end-to-end: HTTP in -> normalization ->
 * detection -> scoring -> policy -> proxy forward -> response out, against a
 * real (throwaway) backend HTTP server - no mocking of the gateway itself.
 *
 * Verifies the two non-negotiable correctness requirements from spec section 23/24:
 *  1. A legitimate backend 404 is returned as 404, never mistranslated to 502.
 *  2. In the default (MONITOR) protection mode, even a clearly malicious
 *     request is still forwarded (ALLOW), because MONITOR never blocks.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewayIntegrationTest {

    private static HttpServer backend;
    private static int backendPort;

    @LocalServerPort
    private int gatewayPort;

    @BeforeAll
    void startBackend() throws IOException {
        backend = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        backendPort = backend.getAddress().getPort();

        backend.createContext("/", exchange -> {
            byte[] body = "hello from backend".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        backend.createContext("/does-not-exist", exchange -> {
            byte[] body = "not found".getBytes();
            exchange.sendResponseHeaders(404, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        backend.start();
    }

    @AfterAll
    void stopBackend() {
        backend.stop(0);
    }

    @DynamicPropertySource
    static void backendUrl(DynamicPropertyRegistry registry) {
        registry.add("calixsentry.backend.base-url", () -> "http://127.0.0.1:" + backendPort);
    }

    private String baseUrl() {
        return "http://localhost:" + gatewayPort;
    }

    @Test
    void normalRequestIsAllowedAndForwarded() {
        TestRestTemplate rest = new TestRestTemplate();
        ResponseEntity<String> response = rest.getForEntity(baseUrl() + "/", String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("hello from backend", response.getBody());
    }

    @Test
    void backendNotFoundIsPropagatedAsNotFoundNeverAsBadGateway() {
        TestRestTemplate rest = new TestRestTemplate();
        ResponseEntity<String> response = rest.getForEntity(baseUrl() + "/does-not-exist", String.class);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode(),
                "A real backend 404 must never be turned into a 502 by the gateway");
    }

    @Test
    void sqlInjectionAttemptIsStillForwardedInDefaultMonitorMode() {
        // Default protection.mode is MONITOR (spec section 18) - CalixSentry must
        // record the detection but still forward the request, never block it.
        TestRestTemplate rest = new TestRestTemplate();
        ResponseEntity<String> response = rest.getForEntity(
                baseUrl() + "/?id=1' OR '1'='1", String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode(),
                "MONITOR mode must never block, even on a detected SQL injection attempt");
    }

    @Test
    void managementDashboardRequiresAuthentication() {
        TestRestTemplate rest = new TestRestTemplate();
        ResponseEntity<String> response = rest.getForEntity(baseUrl() + "/calixsentry/api/status", String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode(),
                "The management API must never be reachable without authentication");
    }

    @Test
    void healthEndpointIsPubliclyReachable() {
        TestRestTemplate rest = new TestRestTemplate();
        ResponseEntity<String> response = rest.getForEntity(baseUrl() + "/health", String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }
}
