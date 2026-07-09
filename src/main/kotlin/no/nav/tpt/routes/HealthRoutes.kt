package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.plugins.kafkaConsumers

fun Route.healthRoutes() {
    get("/isready") {
        val consumers = call.application.kafkaConsumers

        if (consumers != null && consumers.any { !it.isHealthy() }) {
            call.respondText("Kafka consumer unhealthy", ContentType.Text.Plain, HttpStatusCode.ServiceUnavailable)
        } else {
            call.respondText("KIROV REPORTING", ContentType.Text.Plain)
        }
    }
    get("/isalive") {
        call.respondText("A-OK", ContentType.Text.Plain)
    }
}
