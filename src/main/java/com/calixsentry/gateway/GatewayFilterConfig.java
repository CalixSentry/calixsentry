package com.calixsentry.gateway;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Registers WafGatewayFilter to run BEFORE Spring Security's filter chain.
 * This matters because for proxy traffic (anything outside /calixsentry and
 * /actuator) the WAF filter fully handles the request itself and does not
 * call the rest of the chain - it must get first look, so authentication
 * rules meant for the management API never apply to protected application
 * traffic, and so a blocked/rate-limited request never reaches Spring
 * Security or Spring MVC at all.
 */
@Configuration
public class GatewayFilterConfig {

    @Bean
    public FilterRegistrationBean<WafGatewayFilter> wafGatewayFilterRegistration(WafGatewayFilter filter) {
        FilterRegistrationBean<WafGatewayFilter> registration = new FilterRegistrationBean<>(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        // We manage our own bean lifecycle via @Component + constructor injection;
        // prevent Spring Boot from ALSO registering it a second time automatically.
        registration.setEnabled(true);
        return registration;
    }
}
