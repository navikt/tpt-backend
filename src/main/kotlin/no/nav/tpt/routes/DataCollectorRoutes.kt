package no.nav.tpt.routes

import io.ktor.http.HttpStatusCode
import io.ktor.server.auth.authenticate
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import no.nav.tpt.infrastructure.datacollector.DataCollector

fun Route.dataCollectorRoutes(dataCollector: DataCollector) {
    authenticate("auth-bearer") {
        get("/datacollector/{teamSlug}") {
            val teamSlug = call.pathParameters["teamSlug"] ?: ""
            if (teamSlug.isBlank()) {
                call.respond(HttpStatusCode.BadRequest)
                return@get
            }
            call.respond(dataCollector.collectDataFor(teamSlug))
        }
    }
}
