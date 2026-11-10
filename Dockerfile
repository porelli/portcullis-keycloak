# ghcr.io/porelli/portcullis-keycloak: the official Keycloak plus the
# Portcullis sign-in extension (contract §1, §8.1). Every image is pinned
# tag@sha256; Gradle checks every artifact against
# gradle/verification-metadata.xml (--dependency-verification strict).
#
#   docker build --target test .   the tests
#   docker build .                 the image

# The jar is platform-independent: build it once, natively.
FROM --platform=$BUILDPLATFORM gradle:9.8.2-jdk21@sha256:85f8f572045bfb31874d66d7d8a2bd0c17d8cb9ad34b6a4d02f5d552b4b92c04 AS base
WORKDIR /src
COPY settings.gradle.kts build.gradle.kts ./
COPY gradle/verification-metadata.xml gradle/
COPY src src

FROM base AS build
RUN gradle --no-daemon --dependency-verification strict jar

FROM base AS test
RUN gradle --no-daemon --dependency-verification strict test

FROM quay.io/keycloak/keycloak:26.8.1@sha256:3f3c5f8e03c614774b4bd9173b88391fefa4153bfc010d8012d59ad825377332
COPY --from=build /src/build/libs/portcullis-signin.jar /opt/keycloak/providers/
