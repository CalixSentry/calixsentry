# syntax=docker/dockerfile:1

# ---- Build stage: compiles the Spring Boot fat jar ----
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
# Cache dependency resolution as its own layer
RUN mvn -q -B dependency:go-offline || true
COPY src ./src
RUN mvn -q -B clean package -DskipTests

# ---- Runtime stage: small JRE-only image ----
FROM eclipse-temurin:21-jre-jammy
LABEL org.opencontainers.image.title="CalixSentry Engine" \
      org.opencontainers.image.description="Self-hosted behavioral WAF - reverse proxy gateway + detection/policy engine"

RUN useradd --system --create-home --shell /usr/sbin/nologin calixsentry \
    && mkdir -p /data/calixsentry \
    && chown -R calixsentry:calixsentry /data/calixsentry

WORKDIR /app
COPY --from=build /build/target/calixsentry-engine.jar /app/calixsentry-engine.jar

USER calixsentry
EXPOSE 8080 9400
VOLUME ["/data/calixsentry"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/calixsentry-engine.jar"]
