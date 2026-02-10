ARG KEYCLOAK_VERSION=26.5.2

FROM maven:3-eclipse-temurin-21-alpine AS build

COPY src /app/src
COPY pom.xml /app

WORKDIR /app
RUN mvn clean install -U

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS keycloak

COPY --from=build /app/target/keycloak-extension-bundid*.jar /opt/keycloak/providers/keycloak-extension-bundid.jar