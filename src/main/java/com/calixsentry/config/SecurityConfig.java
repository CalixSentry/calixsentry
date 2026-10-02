package com.calixsentry.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Secures the CalixSentry management UI + API (spec section 27).
 *
 * IMPORTANT - MVP scope honestly stated: this is an in-memory user store
 * with three fixed roles (ADMIN, ANALYST, VIEWER) to establish the RBAC
 * foundation the spec asks for. It is NOT a full user-management system
 * (no add/remove users at runtime, no persistence of credentials beyond the
 * generated bootstrap password, no password rotation, no MFA). Those are
 * FUTURE FEATURE work - see docs/ROADMAP.md.
 *
 * Never hard-code credentials: the admin password is read from the
 * CALIXSENTRY_ADMIN_PASSWORD environment variable if set; otherwise a random
 * password is generated at startup, logged once, and written to a
 * restricted-permission file so the administrator can retrieve it - the same
 * pattern Elasticsearch/Kibana use for first-run bootstrap credentials.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private final CalixSentryProperties properties;
    private String resolvedAdminPassword;

    public SecurityConfig(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
        String adminPassword = System.getenv("CALIXSENTRY_ADMIN_PASSWORD");
        if (adminPassword == null || adminPassword.isBlank()) {
            adminPassword = generateAndPersistBootstrapPassword();
        }
        this.resolvedAdminPassword = adminPassword;

        var admin = User.withUsername("admin")
                .password(encoder.encode(adminPassword))
                .roles("ADMIN", "ANALYST", "VIEWER")
                .build();

        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager(admin);

        String analystPassword = System.getenv("CALIXSENTRY_ANALYST_PASSWORD");
        if (analystPassword != null && !analystPassword.isBlank()) {
            manager.createUser(User.withUsername("analyst")
                    .password(encoder.encode(analystPassword)).roles("ANALYST", "VIEWER").build());
        }
        String viewerPassword = System.getenv("CALIXSENTRY_VIEWER_PASSWORD");
        if (viewerPassword != null && !viewerPassword.isBlank()) {
            manager.createUser(User.withUsername("viewer")
                    .password(encoder.encode(viewerPassword)).roles("VIEWER").build());
        }

        return manager;
    }

    private String generateAndPersistBootstrapPassword() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[18];
        random.nextBytes(bytes);
        String password = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        String dataDir = System.getenv("CALIXSENTRY_DATA_DIR");
        if (dataDir == null || dataDir.isBlank()) dataDir = "/data/calixsentry";
        File file = new File(dataDir, "initial-admin-password.txt");
        try {
            File parent = file.getParentFile();
            if (parent != null) parent.mkdirs();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(password);
            }
            file.setReadable(false, false);
            file.setReadable(true, true);
            file.setWritable(false, false);
            file.setWritable(true, true);
        } catch (IOException e) {
            log.warn("Could not persist bootstrap admin password to file: {}", e.getMessage());
        }

        log.warn("=================================================================");
        log.warn(" CalixSentry generated a random initial admin password.");
        log.warn(" Username: admin");
        log.warn(" Password: {}", password);
        log.warn(" (also written to {})", file.getAbsolutePath());
        log.warn(" Set CALIXSENTRY_ADMIN_PASSWORD to control this explicitly.");
        log.warn("=================================================================");
        return password;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        String basePath = properties.getManagement().getBasePath();
        http
            // Public application traffic is handled entirely by WafGatewayFilter, which
            // runs BEFORE this chain (see GatewayFilterConfig) - Spring Security here only
            // governs the /calixsentry management UI/API and /actuator endpoints.
            .csrf(csrf -> csrf.disable()) // stateless JSON API/dashboard; CSRF applies to cookie-based browser form auth
            // The dashboard is plain files (index.html + app.js + app.css) with NO inline script or
            // style, so a strict policy can forbid everything else - a second line of defence
            // against script injection in the admin UI.
            .headers(headers -> headers.contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                            + "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                            + "frame-ancestors 'none'; form-action 'self'")))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/actuator/health", "/health").permitAll()
                    .requestMatchers("/actuator/**").hasRole("ADMIN")
                    // Changing protection mode / automatic blocking / individual rule toggles are
                    // meaningful security decisions - restrict the WRITE side to ADMIN only. GET on
                    // the same paths is covered by the broader ANALYST/VIEWER rule further down.
                    .requestMatchers(org.springframework.http.HttpMethod.PUT, basePath + "/api/protection").hasRole("ADMIN")
                    .requestMatchers(org.springframework.http.HttpMethod.PUT, basePath + "/api/detection/**").hasRole("ADMIN")
                    .requestMatchers(basePath + "/api/blocks/**", basePath + "/api/allowlist/**",
                            basePath + "/api/denylist/**", basePath + "/api/config/**").hasAnyRole("ADMIN", "ANALYST")
                    .requestMatchers(basePath + "/api/**").hasAnyRole("ADMIN", "ANALYST", "VIEWER")
                    .anyRequest().hasAnyRole("ADMIN", "ANALYST", "VIEWER"))
            .httpBasic(basic -> {})
            .formLogin(form -> form.disable());
        return http.build();
    }
}
