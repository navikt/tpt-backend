package no.nav.tpt.routes

import io.ktor.http.HttpStatusCode
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import no.nav.tpt.domain.remediation.CopilotRemediationCallbackRequest
import no.nav.tpt.domain.remediation.CopilotRemediationStartRequest
import no.nav.tpt.plugins.BadRequestException
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies

fun Route.copilotRemediationRoutes() {
    authenticate("auth-bearer") {
        route("/remediations/copilot") {
            get {
                val principal = call.principal<TokenPrincipal>()!!
                val email = principal.preferredUsername
                    ?: throw BadRequestException("preferred_username claim not found in token")
                val repository = call.request.queryParameters["repository"]
                    ?: throw BadRequestException("repository query parameter is required")

                val response = call.dependencies.copilotRemediationService.list(email, principal.groups, repository)
                call.respond(HttpStatusCode.OK, response)
            }

            post {
                val principal = call.principal<TokenPrincipal>()!!
                val email = principal.preferredUsername
                    ?: throw BadRequestException("preferred_username claim not found in token")
                val request = call.receive<CopilotRemediationStartRequest>()

                val response = call.dependencies.copilotRemediationService.start(email, principal.groups, request)
                call.respond(HttpStatusCode.OK, response)
            }

            post("/callback") {
                val principal = call.principal<TokenPrincipal>()!!
                val email = principal.preferredUsername
                    ?: throw BadRequestException("preferred_username claim not found in token")
                val request = call.receive<CopilotRemediationCallbackRequest>()

                val response = call.dependencies.copilotRemediationService.complete(email, principal.groups, request)
                val status = if (response.alreadyStarted) HttpStatusCode.OK else HttpStatusCode.Created
                call.respond(status, response)
            }
        }
    }
}
