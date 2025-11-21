FROM europe-north1-docker.pkg.dev/cgr-nav/pull-through/nav.no/jre:openjdk-21

WORKDIR /app

COPY build/install/appsec-guide/ /app/
COPY openapi/documentation.yaml openapi/documentation.yaml

ENTRYPOINT ["java", "-cp", "/app/lib/*", "no.nav.appsecguide.ApplicationKt"]
