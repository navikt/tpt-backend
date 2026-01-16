package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.plugins.kafkaConsumerService

fun Route.healthRoutes() {
    get("/isready") {
        val kafkaConsumer = call.application.kafkaConsumerService

        if (kafkaConsumer != null && !kafkaConsumer.isHealthy()) {
            call.respondText("Kafka consumer unhealthy", ContentType.Text.Plain, HttpStatusCode.ServiceUnavailable)
        } else {
            call.respondText("KIROV REPORTING", ContentType.Text.Plain)
        }
    }
    get("/isalive") {
        call.respondText("A-OK", ContentType.Text.Plain)
    }
}

