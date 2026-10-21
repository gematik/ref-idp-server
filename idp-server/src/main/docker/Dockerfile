FROM gematik1/osadl-alpine-openjdk21-jre:1.1.0@sha256:8567cc5de502418c2ad8e90666be4cc268751f57ff87f584c35284c215c27bea

ARG COMMIT_HASH
ARG VERSION

LABEL de.gematik.vendor="gematik GmbH" \
      maintainer="software-development@gematik.de" \
      de.gematik.app="IDP Referenzimplementierung" \
      de.gematik.git-repo-name="...idp-global.git" \
      de.gematik.commit-sha=$COMMIT_HASH \
      de.gematik.version=$VERSION

# The STOPSIGNAL instruction sets the system call signal that will be sent to the container to exit
# SIGTERM = 15 - https://de.wikipedia.org/wiki/Signal_(Unix)
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=15s \
            --timeout=10s \
            --start-period=30s \
            --retries=3 \
  CMD ["/usr/bin/wget", "--quiet", "--tries=1", "--spider", \
       "http://localhost:8180/actuator/health"]

# Default USERID and GROUPID
ARG USERID=10000
ARG GROUPID=10000

# Run as User (not root)
USER $USERID:$GROUPID

COPY --chown=$USERID:$GROUPID idp-server*.jar /app/idp-server.jar
WORKDIR /app

CMD ["java", "-jar", "/app/idp-server.jar"]
