plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktor)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.fabrikt)
}

group = "no.nav.tpt"
version = "0.0.1"

kotlin {
    jvmToolchain(25)
}

application {
    mainClass.set("no.nav.tpt.ApplicationKt")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.bundles.ktor)
    implementation(libs.bundles.logging)
    implementation(libs.bundles.database)
    implementation(libs.jakarta.validation.api)
    implementation(libs.kafka.clients)

    testImplementation(libs.bundles.testing)
    testImplementation(platform(libs.junit.bom))
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        events("failed")
    }
}

tasks.register<JavaExec>("runLocalDev") {
    description = "Run the application in local development mode"
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("no.nav.tpt.LocalDevApplicationKt")
}

fabrikt {
    generate("openapi") {
        apiFile = file("src/main/resources/openapi.yaml")
        basePackage = "no.nav.tpt"
        model {
            serializationLibrary = Kotlinx
        }
    }
}