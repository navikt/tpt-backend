plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.ktor)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.fabrikt)
}

group = "no.nav.tpt"
version = "0.0.1"

kotlin {
    jvmToolchain(21)
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
    implementation(libs.valkey.java)
    implementation(libs.jakarta.validation.api)

    testImplementation(libs.bundles.testing)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        events("failed")
    }
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