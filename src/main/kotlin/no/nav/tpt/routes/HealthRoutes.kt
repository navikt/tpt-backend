package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.metrics.TPTMetrics
import no.nav.tpt.plugins.dependencies

fun Route.naisRoutes() {
    route("/internal") {
        get("/isready") {
            val listener = call.dependencies.sseEventLogListener

            if (listener != null && !listener.hasConnected()) {
                call.respondText("SSE event listener not ready", ContentType.Text.Plain, HttpStatusCode.ServiceUnavailable)
            } else {
                call.respondText("KIROV REPORTING", ContentType.Text.Plain)
            }
        }

        get("/isalive") {
            call.respondText("A-OK", ContentType.Text.Plain)
        }

        get("/metrics") {
            call.respond(TPTMetrics.registry.scrape())
        }
    }
}
