FROM europe-north1-docker.pkg.dev/cgr-nav/pull-through/nav.no/jre:openjdk-25@sha256:7afde2c565ed2664bbaf507c2ff02e050cfcb3e5c414ee69e24a8f80e9d1e31c

WORKDIR /app
COPY --chmod=755 build/install/tpt/ /app/
ENV JDK_JAVA_OPTIONS="-XX:InitialRAMPercentage=40 -XX:MaxRAMPercentage=75"
CMD ["-cp", "/app/lib/*", "no.nav.tpt.ApplicationKt"]
