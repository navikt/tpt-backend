FROM europe-north1-docker.pkg.dev/cgr-nav/pull-through/nav.no/jre:openjdk-25

WORKDIR /app

COPY build/install/appsec-guide/ /app/

ENTRYPOINT ["java", "-cp", "/app/lib/*", "no.nav.appsecguide.ApplicationKt"]
