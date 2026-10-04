package com.calixsentry.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Spring Boot's automatic "welcome page" resolution (serving index.html for a
 * directory-style request) only applies to the context root ("/"), not to an
 * arbitrary static subdirectory like /calixsentry/. Without this, navigating
 * to {basePath} or {basePath}/ in a browser 404s even though
 * {basePath}/index.html exists and serves fine - this explicit redirect
 * removes that ambiguity instead of relying on undocumented resource-handler
 * behaviour.
 */
@Configuration
public class DashboardWebConfig implements WebMvcConfigurer {

    private final CalixSentryProperties properties;

    public DashboardWebConfig(CalixSentryProperties properties) {
        this.properties = properties;
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        String basePath = properties.getManagement().getBasePath();
        registry.addRedirectViewController(basePath, basePath + "/index.html");
        registry.addRedirectViewController(basePath + "/", basePath + "/index.html");
    }
}
