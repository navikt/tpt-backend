FROM europe-north1-docker.pkg.dev/cgr-nav/pull-through/nav.no/jre:openjdk-25

WORKDIR /app
COPY --chmod=755 build/install/tpt/ /app/
ENV JDK_JAVA_OPTIONS="-XX:InitialRAMPercentage=40 -XX:MaxRAMPercentage=75"
CMD ["-cp", "/app/lib/*", "no.nav.tpt.ApplicationKt"]
