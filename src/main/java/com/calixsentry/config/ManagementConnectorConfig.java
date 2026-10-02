package com.calixsentry.config;

import org.apache.catalina.connector.Connector;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Opens the dedicated MANAGEMENT port as a second HTTP connector on the same embedded
 * Tomcat (the public gateway port is the normal server.port connector).
 *
 * The management connector binds to calixsentry.server.management-bind-address, which
 * defaults to 127.0.0.1 - the dashboard is then reachable only from the server itself
 * (or through an SSH tunnel / private network), never from the public internet.
 */
@Configuration
public class ManagementConnectorConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> managementConnectorCustomizer(
            CalixSentryProperties properties) {
        return factory -> {
            int port = properties.getServer().getManagementPort();
            if (port <= 0) {
                return; // split disabled: single public port
            }
            Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
            connector.setPort(port);
            connector.setProperty("address", properties.getServer().getManagementBindAddress());
            factory.addAdditionalTomcatConnectors(connector);
        };
    }
}
